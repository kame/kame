/*	$KAME: getaddrinfo.c,v 1.181 2004/04/22 04:03:22 jinmei Exp $	*/

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
 * Issues to be discussed:
 * - Thread safe-ness must be checked.
 * - Return values.  There are nonstandard return values defined and used
 *   in the source code.  This is because RFC2553 is silent about which error
 *   code must be returned for which situation.
 * - freeaddrinfo(NULL).  RFC2553 is silent about it.  XNET 5.2 says it is
 *   invalid.  current code - SEGV on freeaddrinfo(NULL)
 *
 * Note:
 * - The code filters out AFs that are not supported by the kernel,
 *   when globbing NULL hostname (to loopback, or wildcard).  Is it the right
 *   thing to do?  What is the relationship with post-RFC2553 AI_ADDRCONFIG
 *   in ai_flags?
 * - (post-2553) semantics of AI_ADDRCONFIG itself is too vague.
 *   (1) what should we do against numeric hostname (2) what should we do
 *   against NULL hostname (3) what is AI_ADDRCONFIG itself.  AF not ready?
 *   non-loopback address configured?  global address configured?
 *
 * OS specific notes for bsdi3/freebsd2:
 * - We use getipnodebyname() just for thread-safeness.  There's no intent
 *   to let it do PF_UNSPEC (actually we never pass PF_UNSPEC to
 *   getipnodebyname().
 * - The code makes use of following calls when asked to resolver with
 *   ai_family  = PF_UNSPEC:
 *	getipnodebyname(host, AF_INET6);
 *	getipnodebyname(host, AF_INET);
 *   This will result in the following queries if the node is configure to
 *   prefer /etc/hosts than DNS:
 *	lookup /etc/hosts for IPv6 address
 *	lookup DNS for IPv6 address
 *	lookup /etc/hosts for IPv4 address
 *	lookup DNS for IPv4 address
 *   which may not meet people's requirement.
 *   The right thing to happen is to have underlying layer which does
 *   PF_UNSPEC lookup (lookup both) and return chain of addrinfos.
 *   This would result in a bit of code duplicate with _dns_ghbyname() and
 *   friends.
 *
 * OS specific notes for netbsd/openbsd/freebsd4/bsdi4:
 * - To avoid search order issue, we have a big amount of code duplicate
 *   from gethnamaddr.c and some other places.  The issues that there's no
 *   lower layer function to lookup "IPv4 or IPv6" record.  Calling
 *   gethostbyname2 from getaddrinfo will end up in wrong search order, as
 *   presented above.
 *
 * OS specific notes for freebsd4:
 * - 4.[012]-RELEASE supported $GAI.  The code does not.
 * - 4.[012]-RELEASE had EAI_RESNULL code.  The code does not.
 * - 4.[012]-RELEASE turns AI_ADDRCONFIG by default.  the code does not.
 * - 4.[012]-RELEASE allowed classful IPv4 numeric (127.1), the code does not.
 * - EDNS0 support is not available due to resolver differences.
 */

#if defined(__bsdi__) && _BSDI_VERSION >= 199802
#include "port_before.h"
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#ifdef INET6
#include <sys/queue.h>
#if (defined(__FreeBSD__) && __FreeBSD__ >= 3)
#include <net/if_var.h>
#endif
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <netinet6/in6_var.h>	/* XXX */
#endif /* INET6 */
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <ctype.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#if defined(__bsdi__) && _BSDI_VERSION >= 199802
#include <irs.h>
#include "port_after.h"
#include "irs_data.h"
#endif

#define ANY 0
#define YES 1
#define NO  0

static const char in_addrany[] = { 0, 0, 0, 0 };
static const char in_loopback[] = { 127, 0, 0, 1 };
#ifdef INET6
static const char in6_addrany[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
static const char in6_loopback[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
};
#endif

#ifdef INET6
struct policyqueue {
	TAILQ_ENTRY(policyqueue) pc_entry;
	struct in6_addrpolicy pc_policy;
};
#else
struct policyqueue {
	TAILQ_ENTRY(policyqueue) pc_entry;
};
#endif
TAILQ_HEAD(policyhead, policyqueue);

static const struct afd {
	int a_af;
	int a_addrlen;
	int a_socklen;
	int a_off;
	const char *a_addrany;
	const char *a_loopback;
	int a_scoped;
} afdl [] = {
#ifdef INET6
	{PF_INET6, sizeof(struct in6_addr),
	 sizeof(struct sockaddr_in6),
	 offsetof(struct sockaddr_in6, sin6_addr),
	 in6_addrany, in6_loopback, 1},
#endif
	{PF_INET, sizeof(struct in_addr),
	 sizeof(struct sockaddr_in),
	 offsetof(struct sockaddr_in, sin_addr),
	 in_addrany, in_loopback, 0},
	{0, 0, 0, 0, NULL, NULL, 0},
};

struct explore {
	int e_af;
	int e_socktype;
	int e_protocol;
	const char *e_protostr;
	int e_wild;
#define WILD_AF(ex)		((ex)->e_wild & 0x01)
#define WILD_SOCKTYPE(ex)	((ex)->e_wild & 0x02)
#define WILD_PROTOCOL(ex)	((ex)->e_wild & 0x04)
#define WILD_ACTIVE(ex)		((ex)->e_wild & 0x08)
#define WILD_PASSIVE(ex)	((ex)->e_wild & 0x10)
};

static const struct explore explore[] = {
#if 0
	{ PF_LOCAL, ANY, ANY, NULL, 0x01 },
#endif
#ifdef INET6
	{ PF_INET6, SOCK_DGRAM, IPPROTO_UDP, "udp", 0x1f },
	{ PF_INET6, SOCK_DGRAM, IPPROTO_SCTP, "sctp", 0x1f },
	{ PF_INET6, SOCK_STREAM, IPPROTO_SCTP, "sctp", 0x0f },	/* !PASSIVE */
	{ PF_INET6, SOCK_STREAM, IPPROTO_TCP, "sctp", 0x0f },	/* !PASSIVE */
	{ PF_INET6, SOCK_STREAM, IPPROTO_TCP, "tcp", 0x17 },	/* PASSIVE */
	{ PF_INET6, SOCK_STREAM, IPPROTO_SCTP, "sctp", 0x17 },	/* PASSIVE */
	{ PF_INET6, SOCK_SEQPACKET, IPPROTO_SCTP, "sctp", 0x1f },
	{ PF_INET6, SOCK_RAW, ANY, NULL, 0x1d },
#endif
	{ PF_INET, SOCK_DGRAM, IPPROTO_UDP, "udp", 0x1f },
	{ PF_INET, SOCK_DGRAM, IPPROTO_SCTP, "sctp", 0x1f },
	{ PF_INET, SOCK_STREAM, IPPROTO_SCTP, "sctp", 0x0f },	/* !PASSIVE */
	{ PF_INET, SOCK_STREAM, IPPROTO_TCP, "tcp", 0x0f },	/* !PASSIVE */
	{ PF_INET, SOCK_STREAM, IPPROTO_TCP, "tcp", 0x17 },	/* PASSIVE */
	{ PF_INET, SOCK_STREAM, IPPROTO_SCTP, "sctp", 0x17 },	/* PASSIVE */
	{ PF_INET, SOCK_SEQPACKET, IPPROTO_SCTP, "sctp", 0x1f },
	{ PF_INET, SOCK_RAW, ANY, NULL, 0x1d },
	{ -1, 0, 0, NULL, 0 },
};

#ifdef INET6
#define PTON_MAX	16
#else
#define PTON_MAX	4
#endif

#define AIO_SRCFLAG_DEPRECATED 0x1

struct ai_order {
	union {
		struct sockaddr_storage aiou_ss;
		struct sockaddr aiou_sa;
	} aio_src_un;
#define aio_srcsa aio_src_un.aiou_sa
	u_int32_t aio_srcflag;
	int aio_srcscope;
	int aio_dstscope;
	struct policyqueue *aio_srcpolicy;
	struct policyqueue *aio_dstpolicy;
	struct addrinfo *aio_ai;
	int aio_matchlen;
};

/* types for OS dependent portion */
#if defined(__NetBSD__) || defined(__OpenBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 4)
#if 0
struct res_target {
	struct res_target *next;
	const char *name;	/* domain name */
	int qclass, qtype;	/* class and type of query */
	u_char *answer;		/* buffer to put answer */
	int anslen;		/* size of answer buffer */
	int n;			/* result length */
};
#endif

#define MAXPACKET	(64*1024)

typedef union {
	HEADER hdr;
	u_char buf[MAXPACKET];
} querybuf;
#endif

/* functions in OS independent portion */
static int str2number __P((const char *));
static int explore_copy __P((const struct addrinfo *, const struct addrinfo *,
	struct addrinfo **));
static int explore_null __P((const struct addrinfo *,
	const char *, struct addrinfo **));
static int explore_numeric __P((const struct addrinfo *, const char *,
	const char *, struct addrinfo **, const char *));
static int explore_numeric_scope __P((const struct addrinfo *, const char *,
	const char *, struct addrinfo **));
static int get_canonname __P((const struct addrinfo *,
	struct addrinfo *, const char *));
static struct addrinfo *get_ai __P((const struct addrinfo *,
	const struct afd *, const char *));
static struct addrinfo *copy_ai __P((const struct addrinfo *));
static int get_portmatch __P((const struct addrinfo *, const char *));
static int get_port __P((struct addrinfo *, const char *, int));
static const struct afd *find_afd __P((int));
static int addrconfig __P((int));
static void set_source __P((struct ai_order *, struct policyhead *));
static int comp_dst __P((const void *, const void *));
#ifdef INET6
static int ip6_str2scopeid __P((char *, struct sockaddr_in6 *, u_int32_t *));
#endif
static int gai_addr2scopetype __P((struct sockaddr *));

/* functions in OS dependent portion */
static int explore_fqdn __P((const struct addrinfo *, const char *,
	const char *, struct addrinfo **));

/* identify behavior of OS dependent portion */
#if defined(__NetBSD__) || defined(__OpenBSD__) || (defined(__bsdi__) && _BSDI_VERSION >= 199802) || (defined(__FreeBSD__) && __FreeBSD__ >= 4)
#undef USE_GETIPNODEBY
#endif

static int reorder __P((struct addrinfo *));
static void get_addrselectpolicy __P((struct policyhead *));
static void free_addrselectpolicy __P((struct policyhead *));
static struct policyqueue *match_addrselectpolicy __P((struct sockaddr *,
						       struct policyhead *));
static int matchlen __P((struct sockaddr *, struct sockaddr *));

static struct ai_errlist {
	const char *str;
	int code;
} ai_errlist[] = {
	{ "Success",					0, },
#ifdef EAI_ADDRFAMILY
	{ "Address family for hostname not supported",	EAI_ADDRFAMILY, },
#endif
	{ "Temporary failure in name resolution",	EAI_AGAIN, },
	{ "Invalid value for ai_flags",		       	EAI_BADFLAGS, },
	{ "Non-recoverable failure in name resolution", EAI_FAIL, },
	{ "ai_family not supported",			EAI_FAMILY, },
	{ "Memory allocation failure", 			EAI_MEMORY, },
#ifdef EAI_NODATA
	{ "No address associated with hostname", 	EAI_NODATA, },
#endif
	{ "hostname nor servname provided, or not known", EAI_NONAME, },
	{ "servname not supported for ai_socktype",	EAI_SERVICE, },
	{ "ai_socktype not supported", 			EAI_SOCKTYPE, },
	{ "System error returned in errno", 		EAI_SYSTEM, },
	{ "Invalid value for hints",			EAI_BADHINTS, },
	{ "Resolved protocol is unknown",		EAI_PROTOCOL, },
	/* backward compatibility with userland code prior to 2553bis-02 */
#ifndef __OpenBSD__
	{ "Address family for hostname not supported",	1, },
	{ "No address associated with hostname", 	7, },
#else
	{ "Address family for hostname not supported",	-9, },
	{ "No address associated with hostname", 	-5, },
#endif
	{ NULL,						-1, },
};

/* XXX macros that make external reference is BAD. */

#define GET_AI(ai, afd, addr) \
do { \
	/* external reference: pai, error, and label free */ \
	(ai) = get_ai(pai, (afd), (addr)); \
	if ((ai) == NULL) { \
		error = EAI_MEMORY; \
		goto free; \
	} \
} while (/*CONSTCOND*/0)

#define GET_PORT(ai, serv) \
do { \
	/* external reference: error and label free */ \
	error = get_port((ai), (serv), 0); \
	if (error != 0) \
		goto free; \
} while (/*CONSTCOND*/0)

#define GET_CANONNAME(ai, str) \
do { \
	/* external reference: pai, error and label free */ \
	error = get_canonname(pai, (ai), (str)); \
	if (error != 0) \
		goto free; \
} while (/*CONSTCOND*/0)

#define ERR(err) \
do { \
	/* external reference: error, and label bad */ \
	error = (err); \
	goto bad; \
	/*NOTREACHED*/ \
} while (/*CONSTCOND*/0)

#define MATCH_FAMILY(x, y, w) \
	((x) == (y) || (/*CONSTCOND*/(w) && ((x) == PF_UNSPEC || (y) == PF_UNSPEC)))
#define MATCH(x, y, w) \
	((x) == (y) || (/*CONSTCOND*/(w) && ((x) == ANY || (y) == ANY)))

char *
gai_strerror(ecode)
	int ecode;
{
	struct ai_errlist *p;

	for (p = ai_errlist; p->str; p++) {
		if (p->code == ecode)
			return (char *)p->str;
	}
	return "Unknown error";
}

void
freeaddrinfo(ai)
	struct addrinfo *ai;
{
	struct addrinfo *next;

	do {
		next = ai->ai_next;
		if (ai->ai_canonname)
			free(ai->ai_canonname);
		/* no need to free(ai->ai_addr) */
		free(ai);
		ai = next;
	} while (ai);
}

static int
str2number(p)
	const char *p;
{
	char *ep;
	unsigned long v;

	if (*p == '\0')
		return -1;
	ep = NULL;
	errno = 0;
	v = strtoul(p, &ep, 10);
	if (errno == 0 && ep && *ep == '\0' && v <= UINT_MAX)
		return v;
	else
		return -1;
}

int
getaddrinfo(hostname, servname, hints, res)
	const char *hostname, *servname;
	const struct addrinfo *hints;
	struct addrinfo **res;
{
	struct addrinfo sentinel;
	struct addrinfo *cur;
	int error = 0;
	struct addrinfo ai, ai0, *afai;
	struct addrinfo *pai;
	const struct afd *afd;
	const struct explore *ex;
	struct addrinfo *afailist[sizeof(afdl)/sizeof(afdl[0])];
	struct addrinfo *afai_unspec;
	int found;
	int numeric = 0;

	/* ensure we return NULL on errors */
	*res = NULL;

	memset(afailist, 0, sizeof(afailist));
	afai_unspec = NULL;

	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;
	pai = &ai;
	pai->ai_flags = 0;
	pai->ai_family = PF_UNSPEC;
	pai->ai_socktype = ANY;
	pai->ai_protocol = ANY;
	pai->ai_addrlen = 0;
	pai->ai_canonname = NULL;
	pai->ai_addr = NULL;
	pai->ai_next = NULL;

	if (hostname == NULL && servname == NULL)
		return EAI_NONAME;
	if (hints) {
		/* error check for hints */
		if (hints->ai_addrlen || hints->ai_canonname ||
		    hints->ai_addr || hints->ai_next)
			ERR(EAI_BADHINTS); /* xxx */
		if (hints->ai_flags & ~AI_MASK)
			ERR(EAI_BADFLAGS);
		switch (hints->ai_family) {
		case PF_UNSPEC:
		case PF_INET:
#ifdef INET6
		case PF_INET6:
#endif
			break;
		default:
			ERR(EAI_FAMILY);
		}
		memcpy(pai, hints, sizeof(*pai));

		/*
		 * if both socktype/protocol are specified, check if they
		 * are meaningful combination.
		 */
		if (pai->ai_socktype != ANY && pai->ai_protocol != ANY) {
			for (ex = explore; ex->e_af >= 0; ex++) {
				if (!MATCH_FAMILY(pai->ai_family, ex->e_af,
				    WILD_AF(ex)))
					continue;
				if (!MATCH(pai->ai_socktype, ex->e_socktype,
				    WILD_SOCKTYPE(ex)))
					continue;
				if (!MATCH(pai->ai_protocol, ex->e_protocol,
				    WILD_PROTOCOL(ex)))
					continue;

				/* matched */
				break;
			}

			if (ex->e_af < 0) {
				ERR(EAI_BADHINTS);
			}
		}
	}

	/*
	 * check for special cases.  (1) numeric servname is disallowed if
	 * socktype/protocol are left unspecified. (2) servname is disallowed
	 * for raw and other inet{,6} sockets.
	 */
	if (MATCH_FAMILY(pai->ai_family, PF_INET, 1)
#ifdef PF_INET6
	 || MATCH_FAMILY(pai->ai_family, PF_INET6, 1)
#endif
	    ) {
		ai0 = *pai;	/* backup *pai */

		if (pai->ai_family == PF_UNSPEC) {
#ifdef PF_INET6
			pai->ai_family = PF_INET6;
#else
			pai->ai_family = PF_INET;
#endif
		}
		error = get_portmatch(pai, servname);
		if (error)
			ERR(error);

		*pai = ai0;
	}

	ai0 = *pai;

	/*
	 * NULL hostname, or numeric hostname.
	 * If numreic representation of AF1 can be interpreted as FQDN
	 * representation of AF2, we need to think again about the code below.
	 */
	found = 0;
	for (afd = afdl; afd->a_af; afd++) {
		*pai = ai0;

		if (!MATCH_FAMILY(pai->ai_family, afd->a_af, 1))
			continue;

		if (pai->ai_family == PF_UNSPEC)
			pai->ai_family = afd->a_af;

		if (hostname == NULL) {
			/*
			 * filter out AFs that are not supported by the kernel
			 * XXX errno?
			 */
			if (!addrconfig(pai->ai_family))
				continue;
			error = explore_null(pai, servname,
			    &afailist[afd - afdl]);

			/*
			 * Errors from explore_null should be unexpected and
			 * be caught to avoid returning an incomplete result.
			 */
			if (error != 0)
				goto bad;
		} else {
			error = explore_numeric_scope(pai, hostname, servname,
			    &afailist[afd - afdl]);

			/*
			 * explore_numeric_scope returns an error for address
			 * families that do not match that of hostname.
			 * Thus we should not catch the error at this moment. 
			 */
		}

		if (!error && afailist[afd - afdl])
			found++;
	}
	if (found) {
		numeric = 1;
		goto globcopy;
	}

	if (hostname == NULL)
		ERR(EAI_NONAME);	/* used to be EAI_NODATA */
	if (pai->ai_flags & AI_NUMERICHOST)
		ERR(EAI_NONAME);

	/*
	 * hostname as alphabetical name.
	 */
	*pai = ai0;
	error = explore_fqdn(pai, hostname, servname, &afai_unspec);

globcopy:
	for (ex = explore; ex->e_af >= 0; ex++) {
		*pai = ai0;

		if (pai->ai_family == PF_UNSPEC)
			pai->ai_family = ex->e_af;

		if (!MATCH_FAMILY(pai->ai_family, ex->e_af, WILD_AF(ex)))
			continue;
		if (!MATCH(pai->ai_socktype, ex->e_socktype, WILD_SOCKTYPE(ex)))
			continue;
		if (!MATCH(pai->ai_protocol, ex->e_protocol, WILD_PROTOCOL(ex)))
			continue;

#ifdef AI_ADDRCONFIG
		/*
		 * If AI_ADDRCONFIG is specified, check if we are
		 * expected to return the address family or not.
		 */
		if ((pai->ai_flags & AI_ADDRCONFIG) != 0 &&
		    !addrconfig(afd->a_af))
			continue;
#endif

		if ((pai->ai_flags & AI_PASSIVE) != 0 && WILD_PASSIVE(ex))
			;
		else if ((pai->ai_flags & AI_PASSIVE) == 0 && WILD_ACTIVE(ex))
			;
		else
			continue;

		if (pai->ai_family == PF_UNSPEC)
			pai->ai_family = ex->e_af;
		if (pai->ai_socktype == ANY && ex->e_socktype != ANY)
			pai->ai_socktype = ex->e_socktype;
		if (pai->ai_protocol == ANY && ex->e_protocol != ANY)
			pai->ai_protocol = ex->e_protocol;

		/*
		 * if the servname does not match socktype/protocol, ignore it.
		 */
		if (get_portmatch(pai, servname) != 0)
			continue;

		if (afai_unspec)
			afai = afai_unspec;
		else {
			if ((afd = find_afd(pai->ai_family)) == NULL)
				continue;
			/* XXX assumes that afd points inside afdl[] */
			afai = afailist[afd - afdl];
		}
		if (!afai)
			continue;

		error = explore_copy(pai, afai, &cur->ai_next);
		if (error != 0)
			goto bad;

		while (cur && cur->ai_next)
			cur = cur->ai_next;
	}

	/* XXX inhibit errors if we have the result */
	if (sentinel.ai_next)
		error = 0;

	/*
	 * ensure we return either:
	 * - error == 0, non-NULL *res
	 * - error != 0, NULL *res
	 */
	if (error == 0) {
		if (sentinel.ai_next) {
			/*
			 * If the returned entry is for an active connection,
			 * and the given name is not numeric, reorder the
			 * list, so that the application would try the list
			 * in the most efficient order. 
			 */
			if (hints == NULL || !(hints->ai_flags & AI_PASSIVE)) {
				if (!numeric)
					(void)reorder(&sentinel);
			}
			*res = sentinel.ai_next;
		} else
			error = EAI_FAIL;
	}

bad:
	if (afai_unspec)
		freeaddrinfo(afai_unspec);
	for (afd = afdl; afd->a_af; afd++) {
		if (afailist[afd - afdl])
			freeaddrinfo(afailist[afd - afdl]);
	}
	if (!*res)
		if (sentinel.ai_next)
			freeaddrinfo(sentinel.ai_next);
	return error;
}

static int
reorder(sentinel)
	struct addrinfo *sentinel;
{
	struct addrinfo *ai, **aip;
	struct ai_order *aio;
	int i, n;
	struct policyhead policyhead;

	/* count the number of addrinfo elements for sorting. */
	for (n = 0, ai = sentinel->ai_next; ai != NULL; ai = ai->ai_next, n++)
		;

	/*
	 * If the number is small enough, we can skip the reordering process.
	 */
	if (n <= 1)
		return(n);

	/* allocate a temporary array for sort and initialization of it. */
	if ((aio = malloc(sizeof(*aio) * n)) == NULL)
		return(n);	/* give up reordering */
	memset(aio, 0, sizeof(*aio) * n);

	/* retrieve address selection policy from the kernel */
	TAILQ_INIT(&policyhead);
	get_addrselectpolicy(&policyhead);

	for (i = 0, ai = sentinel->ai_next; i < n; ai = ai->ai_next, i++) {
		aio[i].aio_ai = ai;
		aio[i].aio_dstscope = gai_addr2scopetype(ai->ai_addr);
		aio[i].aio_dstpolicy = match_addrselectpolicy(ai->ai_addr,
							      &policyhead);

		set_source(&aio[i], &policyhead);
	}

	/* perform sorting. */
	qsort(aio, n, sizeof(*aio), comp_dst);

	/* reorder the addrinfo chain. */
	for (i = 0, aip = &sentinel->ai_next; i < n; i++) {
		*aip = aio[i].aio_ai;
		aip = &aio[i].aio_ai->ai_next;
	}
	*aip = NULL;

	/* cleanup and return */
	free(aio);
	free_addrselectpolicy(&policyhead);
	return(n);
}

static void
get_addrselectpolicy(head)
	struct policyhead *head;
{
#ifdef INET6
	int mib[] = { CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_ADDRCTLPOLICY };
	size_t l;
	char *buf;
	struct in6_addrpolicy *pol, *ep;

	if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), NULL, &l, NULL, 0) < 0)
		return;
	if ((buf = malloc(l)) == NULL)
		return;
	if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), buf, &l, NULL, 0) < 0) {
		free(buf);
		return;
	}

	ep = (struct in6_addrpolicy *)(buf + l);
	for (pol = (struct in6_addrpolicy *)buf; pol + 1 <= ep; pol++) {
		struct policyqueue *new;

		if ((new = malloc(sizeof(*new))) == NULL) {
			free_addrselectpolicy(head); /* make the list empty */
			break;
		}
		new->pc_policy = *pol;
		TAILQ_INSERT_TAIL(head, new, pc_entry);
	}

	free(buf);
	return;
#else
	return;
#endif
}

static void
free_addrselectpolicy(head)
	struct policyhead *head;
{
	struct policyqueue *ent, *nent;

	for (ent = TAILQ_FIRST(head); ent; ent = nent) {
		nent = TAILQ_NEXT(ent, pc_entry);
		TAILQ_REMOVE(head, ent, pc_entry);
		free(ent);
	}
}

static struct policyqueue *
match_addrselectpolicy(addr, head)
	struct sockaddr *addr;
	struct policyhead *head;
{
#ifdef INET6
	struct policyqueue *ent, *bestent = NULL;
	struct in6_addrpolicy *pol;
	int matchlen, bestmatchlen = -1;
	u_char *mp, *ep, *k, *p, m;
	struct sockaddr_in6 key;

	switch(addr->sa_family) {
	case AF_INET6:
		key = *(struct sockaddr_in6 *)addr;
		break;
	case AF_INET:
		/* convert the address into IPv4-mapped IPv6 address. */
		memset(&key, 0, sizeof(key));
		key.sin6_family = AF_INET6;
		key.sin6_len = sizeof(key);
		key.sin6_addr.s6_addr[10] = 0xff;
		key.sin6_addr.s6_addr[11] = 0xff;
		memcpy(&key.sin6_addr.s6_addr[12],
		       &((struct sockaddr_in *)addr)->sin_addr, 4);
		break;
	default:
		return(NULL);
	}

	for (ent = TAILQ_FIRST(head); ent; ent = TAILQ_NEXT(ent, pc_entry)) {
		pol = &ent->pc_policy;
		matchlen = 0;

		mp = (u_char *)&pol->addrmask.sin6_addr;
		ep = mp + 16;	/* XXX: scope field? */
		k = (u_char *)&key.sin6_addr;
		p = (u_char *)&pol->addr.sin6_addr;
		for (; mp < ep && *mp; mp++, k++, p++) {
			m = *mp;
			if ((*k & m) != *p)
				goto next; /* not match */
			if (m == 0xff) /* short cut for a typical case */
				matchlen += 8;
			else {
				while (m >= 0x80) {
					matchlen++;
					m <<= 1;
				}
			}
		}

		/* matched.  check if this is better than the current best. */
		if (matchlen > bestmatchlen) {
			bestent = ent;
			bestmatchlen = matchlen;
		}

	  next:
		continue;
	}

	return(bestent);
#else
	return(NULL);
#endif

}

static void
set_source(aio, ph)
	struct ai_order *aio;
	struct policyhead *ph;
{
	struct addrinfo ai = *aio->aio_ai;
	struct sockaddr_storage ss;
	int s, srclen;

	/* set unspec ("no source is available"), just in case */
	aio->aio_srcsa.sa_family = AF_UNSPEC;
	aio->aio_srcscope = -1;

	switch(ai.ai_family) {
	case AF_INET:
#ifdef INET6
	case AF_INET6:
#endif
		break;
	default:		/* ignore unsupported AFs explicitly */
		return;
	}

	/* XXX: make a dummy addrinfo to call connect() */
	ai.ai_socktype = SOCK_DGRAM;
	ai.ai_protocol = IPPROTO_UDP; /* is UDP too specific? */
	ai.ai_next = NULL;
	memset(&ss, 0, sizeof(ss));
	memcpy(&ss, ai.ai_addr, ai.ai_addrlen);
	ai.ai_addr = (struct sockaddr *)&ss;
	get_port(&ai, "1", 0);

	/* open a socket to get the source address for the given dst */
	if ((s = socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol)) < 0)
		return;		/* give up */
	if (connect(s, ai.ai_addr, ai.ai_addrlen) < 0)
		goto cleanup;
	srclen = ai.ai_addrlen;
	if (getsockname(s, &aio->aio_srcsa, &srclen) < 0) {
		aio->aio_srcsa.sa_family = AF_UNSPEC;
		goto cleanup;
	}
	aio->aio_srcscope = gai_addr2scopetype(&aio->aio_srcsa);
	aio->aio_srcpolicy = match_addrselectpolicy(&aio->aio_srcsa, ph);
	aio->aio_matchlen = matchlen(&aio->aio_srcsa, aio->aio_ai->ai_addr);
#ifdef INET6
	if (ai.ai_family == AF_INET6) {
		struct in6_ifreq ifr6;
		u_int32_t flags6;

		/* XXX: interface name should not be hardcoded */
		strncpy(ifr6.ifr_name, "lo0", sizeof(ifr6.ifr_name));
		memset(&ifr6, 0, sizeof(ifr6));
		memcpy(&ifr6.ifr_addr, ai.ai_addr, ai.ai_addrlen);
		if (ioctl(s, SIOCGIFAFLAG_IN6, &ifr6) == 0) {
			flags6 = ifr6.ifr_ifru.ifru_flags6;
			if ((flags6 & IN6_IFF_DEPRECATED))
				aio->aio_srcflag |= AIO_SRCFLAG_DEPRECATED;
		}
	}
#endif

  cleanup:
	close(s);
	return;
}

static int
matchlen(src, dst)
	struct sockaddr *src, *dst;
{
	int match = 0;
	u_char *s, *d;
	u_char *lim, r;
	int addrlen;

	switch (src->sa_family) {
#ifdef INET6
	case AF_INET6:
		s = (u_char *)&((struct sockaddr_in6 *)src)->sin6_addr;
		d = (u_char *)&((struct sockaddr_in6 *)dst)->sin6_addr;
		addrlen = sizeof(struct in6_addr);
		lim = s + addrlen;
		break;
#endif
	case AF_INET:
		s = (u_char *)&((struct sockaddr_in6 *)src)->sin6_addr;
		d = (u_char *)&((struct sockaddr_in6 *)dst)->sin6_addr;
		addrlen = sizeof(struct in_addr);
		lim = s + addrlen;
		break;
	default:
		return(0);
	}

	while (s < lim)
		if ((r = (*d++ ^ *s++)) != 0) {
			while (r < addrlen * 8) {
				match++;
				r <<= 1;
			}
			break;
		} else
			match += 8;
	return(match);
}

static int
comp_dst(arg1, arg2)
	const void *arg1, *arg2;
{
	const struct ai_order *dst1 = arg1, *dst2 = arg2;

	/*
	 * Rule 1: Avoid unusable destinations.
	 * XXX: we currently do not consider if an appropriate route exists.
	 */
	if (dst1->aio_srcsa.sa_family != AF_UNSPEC &&
	    dst2->aio_srcsa.sa_family == AF_UNSPEC) {
		return(-1);
	}
	if (dst1->aio_srcsa.sa_family == AF_UNSPEC &&
	    dst2->aio_srcsa.sa_family != AF_UNSPEC) {
		return(1);
	}

	/* Rule 2: Prefer matching scope. */
	if (dst1->aio_dstscope == dst1->aio_srcscope &&
	    dst2->aio_dstscope != dst2->aio_srcscope) {
		return(-1);
	}
	if (dst1->aio_dstscope != dst1->aio_srcscope &&
	    dst2->aio_dstscope == dst2->aio_srcscope) {
		return(1);
	}

	/* Rule 3: Avoid deprecated addresses. */
	if (dst1->aio_srcsa.sa_family != AF_UNSPEC &&
	    dst2->aio_srcsa.sa_family != AF_UNSPEC) {
		if (!(dst1->aio_srcflag & AIO_SRCFLAG_DEPRECATED) &&
		    (dst2->aio_srcflag & AIO_SRCFLAG_DEPRECATED)) {
			return(-1);
		}
		if ((dst1->aio_srcflag & AIO_SRCFLAG_DEPRECATED) &&
		    !(dst2->aio_srcflag & AIO_SRCFLAG_DEPRECATED)) {
			return(1);
		}
	}

	/* Rule 4: Prefer home addresses. */
	/* XXX: not implemented yet */

	/* Rule 5: Prefer matching label. */
#ifdef INET6
	if (dst1->aio_srcpolicy && dst1->aio_dstpolicy &&
	    dst1->aio_srcpolicy->pc_policy.label ==
	    dst1->aio_dstpolicy->pc_policy.label &&
	    (dst2->aio_srcpolicy == NULL || dst2->aio_dstpolicy == NULL ||
	     dst2->aio_srcpolicy->pc_policy.label !=
	     dst2->aio_dstpolicy->pc_policy.label)) {
		return(-1);
	}
	if (dst2->aio_srcpolicy && dst2->aio_dstpolicy &&
	    dst2->aio_srcpolicy->pc_policy.label ==
	    dst2->aio_dstpolicy->pc_policy.label &&
	    (dst1->aio_srcpolicy == NULL || dst1->aio_dstpolicy == NULL ||
	     dst1->aio_srcpolicy->pc_policy.label !=
	     dst1->aio_dstpolicy->pc_policy.label)) {
		return(1);
	}
#endif

	/* Rule 6: Prefer higher precedence. */
#ifdef INET6
	if (dst1->aio_dstpolicy &&
	    (dst2->aio_dstpolicy == NULL ||
	     dst1->aio_dstpolicy->pc_policy.preced >
	     dst2->aio_dstpolicy->pc_policy.preced)) {
		return(-1);
	}
	if (dst2->aio_dstpolicy &&
	    (dst1->aio_dstpolicy == NULL ||
	     dst2->aio_dstpolicy->pc_policy.preced >
	     dst1->aio_dstpolicy->pc_policy.preced)) {
		return(1);
	}
#endif

	/* Rule 7: Prefer native transport. */
	/* XXX: not implemented yet */

	/* Rule 8: Prefer smaller scope. */
	if (dst1->aio_dstscope >= 0 &&
	    dst1->aio_dstscope < dst2->aio_dstscope) {
		return(-1);
	}
	if (dst2->aio_dstscope >= 0 &&
	    dst2->aio_dstscope < dst1->aio_dstscope) {
		return(1);
	}

	/*
	 * Rule 9: Use longest matching prefix.
	 * We compare the match length in a same AF only.
	 */
	if (dst1->aio_ai->ai_addr->sa_family ==
	    dst2->aio_ai->ai_addr->sa_family) {
		if (dst1->aio_matchlen > dst2->aio_matchlen) {
			return(-1);
		}
		if (dst1->aio_matchlen < dst2->aio_matchlen) {
			return(1);
		}
	}

	/* Rule 10: Otherwise, leave the order unchanged. */
	return(-1);
}

/*
 * Copy from scope.c.
 * XXX: we should standardize the functions and link them as standard
 * library.
 */
static int
gai_addr2scopetype(sa)
	struct sockaddr *sa;
{
#ifdef INET6
	struct sockaddr_in6 *sa6;
#endif
	struct sockaddr_in *sa4;

	switch(sa->sa_family) {
#ifdef INET6
	case AF_INET6:
		sa6 = (struct sockaddr_in6 *)sa;
		if (IN6_IS_ADDR_MULTICAST(&sa6->sin6_addr)) {
			/* just use the scope field of the multicast address */
			return(sa6->sin6_addr.s6_addr[2] & 0x0f);
		}
		/*
		 * Unicast addresses: map scope type to corresponding scope
		 * value defined for multcast addresses.
		 * XXX: hardcoded scope type values are bad...
		 */
		if (IN6_IS_ADDR_LOOPBACK(&sa6->sin6_addr))
			return(1); /* node local scope */
		if (IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr))
			return(2); /* link-local scope */
		if (IN6_IS_ADDR_SITELOCAL(&sa6->sin6_addr))
			return(5); /* site-local scope */
		return(14);	/* global scope */
		break;
#endif
	case AF_INET:
		/*
		 * IPv4 pseudo scoping according to RFC 3484.
		 */
		sa4 = (struct sockaddr_in *)sa;
		/* IPv4 autoconfiguration addresses have link-local scope. */
		if (((u_char *)&sa4->sin_addr)[0] == 169 &&
		    ((u_char *)&sa4->sin_addr)[1] == 254)
			return(2);
		/* Private addresses have site-local scope. */
		if (((u_char *)&sa4->sin_addr)[0] == 10 ||
		    (((u_char *)&sa4->sin_addr)[0] == 172 &&
		     (((u_char *)&sa4->sin_addr)[1] & 0xf0) == 16) ||
		    (((u_char *)&sa4->sin_addr)[0] == 192 &&
		     ((u_char *)&sa4->sin_addr)[1] == 168))
			return(5);
		/* Loopback addresses have link-local scope. */
		if (((u_char *)&sa4->sin_addr)[0] == 127)
			return(2);
		return(14);
		break;
	default:
		errno = EAFNOSUPPORT; /* is this a good error? */
		return(-1);
	}
}

static int
explore_copy(pai, src0, res)
	const struct addrinfo *pai;	/* seed */
	const struct addrinfo *src0;	/* source */
	struct addrinfo **res;
{
	int error;
	struct addrinfo sentinel, *cur;
	const struct addrinfo *src;

	error = 0;
	sentinel.ai_next = NULL;
	cur = &sentinel;

	for (src = src0; src != NULL; src = src->ai_next) {
		if (src->ai_family != pai->ai_family)
			continue;

		cur->ai_next = copy_ai(src);
		if (!cur->ai_next) {
			error = EAI_MEMORY;
			goto fail;
		}

		cur->ai_next->ai_socktype = pai->ai_socktype;
		cur->ai_next->ai_protocol = pai->ai_protocol;
		cur = cur->ai_next;
	}

	*res = sentinel.ai_next;
	return 0;

fail:
	freeaddrinfo(sentinel.ai_next);
	return error;
}

/*
 * hostname == NULL.
 * passive socket -> anyaddr (0.0.0.0 or ::)
 * non-passive socket -> localhost (127.0.0.1 or ::1)
 * The AI_CANONNAME flag is only meaningful when nodename is non NULL
 * (RFC3493), so we don't have to worry about it in this function. 
 */
static int
explore_null(pai, servname, res)
	const struct addrinfo *pai;
	const char *servname;
	struct addrinfo **res;
{
	const struct afd *afd;
	struct addrinfo *ai;
	int error;

	*res = NULL;
	ai = NULL;

	afd = find_afd(pai->ai_family);
	if (afd == NULL)
		return 0;

	if (pai->ai_flags & AI_PASSIVE) {
		GET_AI(ai, afd, afd->a_addrany);
		GET_PORT(ai, servname);
	} else {
		GET_AI(ai, afd, afd->a_loopback);
		GET_PORT(ai, servname);
	}

	*res = ai;
	return 0;

free:
	if (ai != NULL)
		freeaddrinfo(ai);
	return error;
}

/*
 * numeric hostname
 */
static int
explore_numeric(pai, hostname, servname, res, canonname)
	const struct addrinfo *pai;
	const char *hostname;
	const char *servname;
	struct addrinfo **res;
	const char *canonname;
{
	const struct afd *afd;
	struct addrinfo *ai;
	int error;
	char pton[PTON_MAX];

	*res = NULL;
	ai = NULL;

	afd = find_afd(pai->ai_family);
	if (afd == NULL)
		return 0;

	switch (afd->a_af) {
	case AF_INET:
		/*
		 * RFC3493 requires getaddrinfo() to accept AF_INET formats
		 * that are accepted by inet_addr() and its family.  The
		 * accepted forms include the "classful" one, which inet_pton
		 * does not accept.  So we need to separate the case for
		 * AF_INET.
		 */
		if (inet_aton(hostname, (struct in_addr *)pton) != 1)
			return 0;
		break;
	default:
		if (inet_pton(afd->a_af, hostname, pton) != 1)
			return 0;
		break;
	}

	if (pai->ai_family == afd->a_af) {
		GET_AI(ai, afd, pton);
		GET_PORT(ai, servname);
		if ((pai->ai_flags & AI_CANONNAME)) {
			/*
			 * Set the numeric address itself as the canonical
			 * name, based on a clarification in RFC3493.
			 */
			GET_CANONNAME(ai, canonname);
		}
	} else {
		/*
		 * XXX: This should not happen since we already matched the AF
		 * by find_afd.
		 */
		ERR(EAI_FAMILY);
	}

	*res = ai;
	return 0;

free:
bad:
	if (ai != NULL)
		freeaddrinfo(ai);
	return error;
}

/*
 * numeric hostname with scope
 */
static int
explore_numeric_scope(pai, hostname, servname, res)
	const struct addrinfo *pai;
	const char *hostname;
	const char *servname;
	struct addrinfo **res;
{
#if !defined(SCOPE_DELIMITER) || !defined(INET6)
	return explore_numeric(pai, hostname, servname, res, hostname);
#else
	const struct afd *afd;
	struct addrinfo *cur;
	int error;
	char *cp, *hostname2 = NULL, *scope, *addr;
	struct sockaddr_in6 *sin6;

	afd = find_afd(pai->ai_family);
	if (afd == NULL)
		return 0;

	if (!afd->a_scoped)
		return explore_numeric(pai, hostname, servname, res, hostname);

	cp = strchr(hostname, SCOPE_DELIMITER);
	if (cp == NULL)
		return explore_numeric(pai, hostname, servname, res, hostname);

	/*
	 * Handle special case of <scoped_address><delimiter><scope id>
	 */
	hostname2 = strdup(hostname);
	if (hostname2 == NULL)
		return EAI_MEMORY;
	/* terminate at the delimiter */
	hostname2[cp - hostname] = '\0';
	addr = hostname2;
	scope = cp + 1;

	error = explore_numeric(pai, addr, servname, res, hostname);
	if (error == 0) {
		u_int32_t scopeid;

		for (cur = *res; cur; cur = cur->ai_next) {
			if (cur->ai_family != AF_INET6)
				continue;
			sin6 = (struct sockaddr_in6 *)cur->ai_addr;
			if (ip6_str2scopeid(scope, sin6, &scopeid) == -1) {
				free(hostname2);
				freeaddrinfo(*res);
				*res = NULL;
				return(EAI_NONAME); /* XXX: is return OK? */
			}
			sin6->sin6_scope_id = scopeid;
		}
	}

	free(hostname2);

	if (error && *res) {
		freeaddrinfo(*res);
		*res = NULL;
	}
	return error;
#endif
}

static int
get_canonname(pai, ai, str)
	const struct addrinfo *pai;
	struct addrinfo *ai;
	const char *str;
{
	if ((pai->ai_flags & AI_CANONNAME) != 0) {
		ai->ai_canonname = strdup(str);
		if (ai->ai_canonname == NULL)
			return EAI_MEMORY;
	}
	return 0;
}

static struct addrinfo *
get_ai(pai, afd, addr)
	const struct addrinfo *pai;
	const struct afd *afd;
	const char *addr;
{
	char *p;
	struct addrinfo *ai;

	ai = (struct addrinfo *)malloc(sizeof(struct addrinfo)
		+ (afd->a_socklen));
	if (ai == NULL)
		return NULL;

	memcpy(ai, pai, sizeof(struct addrinfo));
	ai->ai_addr = (struct sockaddr *)(void *)(ai + 1);
	memset(ai->ai_addr, 0, (size_t)afd->a_socklen);
	ai->ai_addr->sa_len = afd->a_socklen;
	ai->ai_addrlen = afd->a_socklen;
	ai->ai_addr->sa_family = ai->ai_family = afd->a_af;
	p = (char *)(void *)(ai->ai_addr);
	memcpy(p + afd->a_off, addr, (size_t)afd->a_addrlen);
	return ai;
}

/* XXX need to malloc() the same way we do from other functions! */
static struct addrinfo *
copy_ai(pai)
	const struct addrinfo *pai;
{
	struct addrinfo *ai;
	size_t l;

	l = sizeof(*ai) + pai->ai_addrlen;
	if ((ai = (struct addrinfo *)malloc(l)) == NULL)
		return NULL;
	memset(ai, 0, l);
	memcpy(ai, pai, sizeof(*ai));
	ai->ai_addr = (struct sockaddr *)(void *)(ai + 1);
	memcpy(ai->ai_addr, pai->ai_addr, pai->ai_addrlen);

	if (pai->ai_canonname) {
		l = strlen(pai->ai_canonname) + 1;
		if ((ai->ai_canonname = malloc(l)) == NULL) {
			free(ai);
			return NULL;
		}
		strlcpy(ai->ai_canonname, pai->ai_canonname, l);
	} else {
		/* just to make sure */
		ai->ai_canonname = NULL;
	}

	ai->ai_next = NULL;

	return ai;
}

static int
get_portmatch(ai, servname)
	const struct addrinfo *ai;
	const char *servname;
{

	/* get_port does not touch first argument when matchonly == 1. */
	/* LINTED const cast */
	return get_port((struct addrinfo *)ai, servname, 1);
}

static int
get_port(ai, servname, matchonly)
	struct addrinfo *ai;
	const char *servname;
	int matchonly;
{
	const char *proto;
	struct servent *sp;
	int port;
	int allownumeric;

	if (servname == NULL)
		return 0;
	switch (ai->ai_family) {
	case AF_INET:
#ifdef AF_INET6
	case AF_INET6:
#endif
		break;
	default:
		return 0;
	}

	switch (ai->ai_socktype) {
	case SOCK_RAW:
		return EAI_SERVICE;
	case SOCK_DGRAM:
	case SOCK_STREAM:
	case SOCK_SEQPACKET:
		allownumeric = 1;
		break;
	case ANY:
		allownumeric = 0;
		break;
	default:
		return EAI_SOCKTYPE;
	}

	port = str2number(servname);
	if (port >= 0) {
		if (!allownumeric)
			return EAI_SERVICE;
		if (port < 0 || port > 65535)
			return EAI_SERVICE;
		port = htons(port);
	} else {
		if (ai->ai_flags & AI_NUMERICSERV)
			return EAI_NONAME;

		switch (ai->ai_protocol) {
		case IPPROTO_UDP:
			proto = "udp";
			break;
		case IPPROTO_TCP:
			proto = "tcp";
			break;
		case IPPROTO_SCTP:
			proto = "sctp";
			break;
		default:
			proto = NULL;
			break;
		}

		if ((sp = getservbyname(servname, proto)) == NULL)
			return EAI_SERVICE;
		port = sp->s_port;
	}

	if (!matchonly) {
		switch (ai->ai_family) {
		case AF_INET:
			((struct sockaddr_in *)(void *)
			    ai->ai_addr)->sin_port = port;
			break;
#ifdef INET6
		case AF_INET6:
			((struct sockaddr_in6 *)(void *)
			    ai->ai_addr)->sin6_port = port;
			break;
#endif
		}
	}

	return 0;
}

static const struct afd *
find_afd(af)
	int af;
{
	const struct afd *afd;

	if (af == PF_UNSPEC)
		return NULL;
	for (afd = afdl; afd->a_af; afd++) {
		if (afd->a_af == af)
			return afd;
	}
	return NULL;
}

/*
 * post-2553: AI_ADDRCONFIG check.  if we use getipnodeby* as backend, backend
 * will take care of it.
 * the semantics of AI_ADDRCONFIG is not defined well.  we are not sure
 * if the code is right or not.
 */
static int
addrconfig(af)
	int af;
{
#ifdef USE_GETIPNODEBY
	return 1;
#else
	int s;

	/* XXX errno */
	s = socket(af, SOCK_DGRAM, 0);
	if (s < 0) {
		if (errno != EMFILE)
			return 0;
	} else
		close(s);
	return 1;
#endif
}

#ifdef INET6
/* convert a string to a scope identifier. XXX: IPv6 specific */
static int
ip6_str2scopeid(scope, sin6, scopeid)
	char *scope;
	struct sockaddr_in6 *sin6;
	u_int32_t *scopeid;
{
	u_long lscopeid;
	struct in6_addr *a6 = &sin6->sin6_addr;
	char *ep;

	/* empty scopeid portion is invalid */
	if (*scope == '\0')
		return -1;

	if (IN6_IS_ADDR_LINKLOCAL(a6) || IN6_IS_ADDR_MC_LINKLOCAL(a6) ||
	    IN6_IS_ADDR_MC_NODELOCAL(a6)) {
		/*
		 * We currently assume a one-to-one mapping between links
		 * and interfaces, so we simply use interface indices for
		 * like-local scopes.
		 */
		*scopeid = if_nametoindex(scope);
		if (*scopeid == 0)
			goto trynumeric;
		return 0;
	}

	/* still unclear about literal, allow numeric only - placeholder */
	if (IN6_IS_ADDR_SITELOCAL(a6) || IN6_IS_ADDR_MC_SITELOCAL(a6))
		goto trynumeric;
	if (IN6_IS_ADDR_MC_ORGLOCAL(a6))
		goto trynumeric;
	else
		goto trynumeric;	/* global */

	/* try to convert to a numeric id as a last resort */
trynumeric:
	errno = 0;
	lscopeid = strtoul(scope, &ep, 10);
	*scopeid = (u_int32_t)(lscopeid & 0xffffffffUL);
	if (errno == 0 && ep && *ep == '\0' && *scopeid == lscopeid)
		return 0;
	else
		return -1;
}
#endif

/*
 * OS dependent portions below
 */

#if !defined(__NetBSD__) && !defined(__OpenBSD__) && !(defined(__bsdi__) && _BSDI_VERSION >= 199802) && !(defined(__FreeBSD__) && __FreeBSD__ >= 4)
/*
 * FQDN hostname, DNS lookup
 */
static int
explore_fqdn(pai, hostname, servname, res)
	const struct addrinfo *pai;
	const char *hostname;
	const char *servname;
	struct addrinfo **res;
{
	struct hostent *hp;
	int h_error;
	int af;
	char **aplist = NULL, *apbuf = NULL;
	char *ap;
	struct addrinfo sentinel, *cur;
	int i;
#ifndef USE_GETIPNODEBY
	int naddrs;
#endif
	const struct afd *afd;
	int error = 0;
#if 0
	struct addrinfo pai4;
#ifdef INET6
	struct addrinfo pai6;
#endif
#endif

	*res = NULL;
	sentinel.ai_next = NULL;
	cur = &sentinel;

	/*
	 * if the servname does not match socktype/protocol, ignore it.
	 */
	if (get_portmatch(pai, servname) != 0)
		return 0;

	afd = find_afd(pai->ai_family);
	if (afd == NULL)
		return 0;

#ifdef USE_GETIPNODEBY
	hp = getipnodebyname(hostname, pai->ai_family,
	    pai->ai_flags & AI_ADDRCONFIG, &h_error);
#else
#ifdef HAVE_GETHOSTBYNAME2
	hp = gethostbyname2(hostname, pai->ai_family);
#else
	if (pai->ai_family != AF_INET)
		return 0;
	hp = gethostbyname(hostname);
#endif /*HAVE_GETHOSTBYNAME2*/
#ifdef HAVE_H_ERRNO
	h_error = h_errno;
#else
	h_error = EINVAL;
#endif
#endif /*USE_GETIPNODEBY*/

	if (hp == NULL) {
		switch (h_error) {
		case HOST_NOT_FOUND:
		case NO_DATA:
			error = EAI_NONAME;
			break;
		case TRY_AGAIN:
			error = EAI_AGAIN;
			break;
		case NO_RECOVERY:
		case NETDB_INTERNAL:
		default:
			error = EAI_FAIL;
			break;
		}
	} else if ((hp->h_name == NULL) || (hp->h_name[0] == 0)
			|| (hp->h_addr_list[0] == NULL)) {
#ifdef USE_GETIPNODEBY
		freehostent(hp);
#endif
		hp = NULL;
		error = EAI_FAIL;
	}

	if (hp == NULL)
		goto free;

#ifdef USE_GETIPNODEBY
	aplist = hp->h_addr_list;
#else
	/*
	 * hp will be overwritten if we use gethostbyname2().
	 * always deep copy for simplification.
	 */
	for (naddrs = 0; hp->h_addr_list[naddrs] != NULL; naddrs++)
		;
	naddrs++;
	aplist = (char **)malloc(sizeof(aplist[0]) * naddrs);
	apbuf = (char *)malloc((size_t)hp->h_length * naddrs);
	if (aplist == NULL || apbuf == NULL) {
		error = EAI_MEMORY;
		goto free;
	}
	memset(aplist, 0, sizeof(aplist[0]) * naddrs);
	for (i = 0; i < naddrs; i++) {
		if (hp->h_addr_list[i] == NULL) {
			aplist[i] = NULL;
			continue;
		}
		memcpy(&apbuf[i * hp->h_length], hp->h_addr_list[i],
			(size_t)hp->h_length);
		aplist[i] = &apbuf[i * hp->h_length];
	}
#endif

	for (i = 0; aplist[i] != NULL; i++) {
		af = hp->h_addrtype;
		ap = aplist[i];
#ifdef INET6
		if (af == AF_INET6
		 && IN6_IS_ADDR_V4MAPPED((struct in6_addr *)ap)) {
			af = AF_INET;
			ap = ap + sizeof(struct in6_addr)
				- sizeof(struct in_addr);
		}
#endif

		if (af != pai->ai_family)
			continue;

		GET_AI(cur->ai_next, afd, ap);
		GET_PORT(cur->ai_next, servname);
		if ((pai->ai_flags & AI_CANONNAME) != 0) {
			/*
			 * RFC2553 says that ai_canonname will be set only for
			 * the first element.  we do it for all the elements,
			 * just for convenience.
			 */
			GET_CANONNAME(cur->ai_next, hp->h_name);
		}

		while (cur && cur->ai_next)
			cur = cur->ai_next;
	}

	*res = sentinel.ai_next;
	return 0;

free:
#ifdef USE_GETIPNODEBY
	if (hp)
		freehostent(hp);
#endif
	if (aplist)
		free(aplist);
	if (apbuf)
		free(apbuf);
	if (sentinel.ai_next)
		freeaddrinfo(sentinel.ai_next);
	return error;
}

#elif defined(__NetBSD__)

#include <syslog.h>
#include <stdarg.h>
#include <nsswitch.h>

#ifdef YP
#include <rpc/rpc.h>
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>
#endif

static const ns_src default_dns_files[] = {
	{ NSSRC_FILES, 	NS_SUCCESS },
	{ NSSRC_DNS, 	NS_SUCCESS },
	{ 0 }
};

static struct addrinfo *getanswer __P((const querybuf *, int, const char *,
	int, const struct addrinfo *));

static int _dns_getaddrinfo __P((void *, void *, va_list));
static void _sethtent __P((void));
static void _endhtent __P((void));
static struct addrinfo *_gethtent __P((const char *, const struct addrinfo *));
static int _files_getaddrinfo __P((void *, void *, va_list));
#ifdef YP
static struct addrinfo *_yphostent __P((char *, const struct addrinfo *));
static int _yp_getaddrinfo __P((void *, void *, va_list));
#endif

static int res_queryN __P((const char *, struct res_target *));
static int res_searchN __P((const char *, struct res_target *));
static int res_querydomainN __P((const char *, const char *,
	struct res_target *));

/*
 * FQDN hostname, DNS lookup
 */
static int
explore_fqdn(pai, hostname, servname, res)
	const struct addrinfo *pai;
	const char *hostname;
	const char *servname;
	struct addrinfo **res;
{
	struct addrinfo *result;
	struct addrinfo *cur;
	int error = 0;
	static const ns_dtab dtab[] = {
		NS_FILES_CB(_files_getaddrinfo, NULL)
		{ NSSRC_DNS, _dns_getaddrinfo, NULL },	/* force -DHESIOD */
		NS_NIS_CB(_yp_getaddrinfo, NULL)
		{ 0 }
	};

	result = NULL;

	/*
	 * if the servname does not match socktype/protocol, ignore it.
	 */
	if (get_portmatch(pai, servname) != 0)
		return 0;

	switch (nsdispatch(&result, dtab, NSDB_HOSTS, "getaddrinfo",
			default_dns_files, hostname, pai)) {
	case NS_TRYAGAIN:
		error = EAI_AGAIN;
		goto free;
	case NS_UNAVAIL:
		error = EAI_FAIL;
		goto free;
	case NS_NOTFOUND:
		error = EAI_NONAME;
		goto free;
	case NS_SUCCESS:
		error = 0;
		for (cur = result; cur; cur = cur->ai_next) {
			GET_PORT(cur, servname);
			/* canonname should already be filled. */
		}
		break;
	}

	*res = result;

	return 0;

free:
	if (result)
		freeaddrinfo(result);
	return error;
}

/* code duplicate with gethnamaddr.c */

static const char AskedForGot[] =
	"gethostby*.getanswer: asked for \"%s\", got \"%s\"";
static FILE *hostf = NULL;

static struct addrinfo *
getanswer(answer, anslen, qname, qtype, pai)
	const querybuf *answer;
	int anslen;
	const char *qname;
	int qtype;
	const struct addrinfo *pai;
{
	struct addrinfo sentinel, *cur;
	struct addrinfo ai;
	const struct afd *afd;
	char *canonname;
	const HEADER *hp;
	const u_char *cp;
	int n;
	const u_char *eom;
	char *bp, *ep;
	int type, class, ancount, qdcount;
	int haveanswer, had_error;
	char tbuf[MAXDNAME];
	int (*name_ok) __P((const char *));
	char hostbuf[8*1024];

	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;

	canonname = NULL;
	eom = answer->buf + anslen;
	switch (qtype) {
	case T_A:
	case T_AAAA:
	case T_ANY:	/*use T_ANY only for T_A/T_AAAA lookup*/
		name_ok = res_hnok;
		break;
	default:
		return (NULL);	/* XXX should be abort(); */
	}
	/*
	 * find first satisfactory answer
	 */
	hp = &answer->hdr;
	ancount = ntohs(hp->ancount);
	qdcount = ntohs(hp->qdcount);
	bp = hostbuf;
	ep = hostbuf + sizeof hostbuf;
	cp = answer->buf + HFIXEDSZ;
	if (qdcount != 1) {
		h_errno = NO_RECOVERY;
		return (NULL);
	}
	n = dn_expand(answer->buf, eom, cp, bp, ep - bp);
	if ((n < 0) || !(*name_ok)(bp)) {
		h_errno = NO_RECOVERY;
		return (NULL);
	}
	cp += n + QFIXEDSZ;
	if (qtype == T_A || qtype == T_AAAA || qtype == T_ANY) {
		/* res_send() has already verified that the query name is the
		 * same as the one we sent; this just gets the expanded name
		 * (i.e., with the succeeding search-domain tacked on).
		 */
		n = strlen(bp) + 1;		/* for the \0 */
		if (n >= MAXHOSTNAMELEN) {
			h_errno = NO_RECOVERY;
			return (NULL);
		}
		canonname = bp;
		bp += n;
		/* The qname can be abbreviated, but h_name is now absolute. */
		qname = canonname;
	}
	haveanswer = 0;
	had_error = 0;
	while (ancount-- > 0 && cp < eom && !had_error) {
		n = dn_expand(answer->buf, eom, cp, bp, ep - bp);
		if ((n < 0) || !(*name_ok)(bp)) {
			had_error++;
			continue;
		}
		cp += n;			/* name */
		type = _getshort(cp);
 		cp += INT16SZ;			/* type */
		class = _getshort(cp);
 		cp += INT16SZ + INT32SZ;	/* class, TTL */
		n = _getshort(cp);
		cp += INT16SZ;			/* len */
		if (class != C_IN) {
			/* XXX - debug? syslog? */
			cp += n;
			continue;		/* XXX - had_error++ ? */
		}
		if ((qtype == T_A || qtype == T_AAAA || qtype == T_ANY) &&
		    type == T_CNAME) {
			n = dn_expand(answer->buf, eom, cp, tbuf, sizeof tbuf);
			if ((n < 0) || !(*name_ok)(tbuf)) {
				had_error++;
				continue;
			}
			cp += n;
			/* Get canonical name. */
			n = strlen(tbuf) + 1;	/* for the \0 */
			if (n > ep - bp || n >= MAXHOSTNAMELEN) {
				had_error++;
				continue;
			}
			strlcpy(bp, tbuf, ep - bp);
			canonname = bp;
			bp += n;
			continue;
		}
		if (qtype == T_ANY) {
			if (!(type == T_A || type == T_AAAA)) {
				cp += n;
				continue;
			}
		} else if (type != qtype) {
			if (type != T_KEY && type != T_SIG)
				syslog(LOG_NOTICE|LOG_AUTH,
	       "gethostby*.getanswer: asked for \"%s %s %s\", got type \"%s\"",
				       qname, p_class(C_IN), p_type(qtype),
				       p_type(type));
			cp += n;
			continue;		/* XXX - had_error++ ? */
		}
		switch (type) {
		case T_A:
		case T_AAAA:
			if (strcasecmp(canonname, bp) != 0) {
				syslog(LOG_NOTICE|LOG_AUTH,
				       AskedForGot, canonname, bp);
				cp += n;
				continue;	/* XXX - had_error++ ? */
			}
			if (type == T_A && n != INADDRSZ) {
				cp += n;
				continue;
			}
			if (type == T_AAAA && n != IN6ADDRSZ) {
				cp += n;
				continue;
			}
#ifdef FILTER_V4MAPPED
			if (type == T_AAAA) {
				struct in6_addr in6;
				memcpy(&in6, cp, sizeof(in6));
				if (IN6_IS_ADDR_V4MAPPED(&in6)) {
					cp += n;
					continue;
				}
			}
#endif
			if (!haveanswer) {
				int nn;

				canonname = bp;
				nn = strlen(bp) + 1;	/* for the \0 */
				bp += nn;
			}

			/* don't overwrite pai */
			ai = *pai;
			switch (type) {
			case T_A:
				ai.ai_family = AF_INET;
				break;
			case T_AAAA:
				ai.ai_family = AF_INET6;
				break;
			}
			afd = find_afd(ai.ai_family);
			if (afd == NULL) {
				cp += n;
				continue;
			}
			switch (type) {
			case T_A:
			case T_AAAA:
				cur->ai_next = get_ai(&ai, afd,
				    (const char *)cp);
				break;
			}
			if (cur->ai_next == NULL)
				had_error++;
			while (cur && cur->ai_next)
				cur = cur->ai_next;
			cp += n;
			break;
		default:
			abort();
		}
		if (!had_error)
			haveanswer++;
	}
	if (haveanswer) {
		if (!canonname)
			(void)get_canonname(pai, sentinel.ai_next, qname);
		else
			(void)get_canonname(pai, sentinel.ai_next, canonname);
		h_errno = NETDB_SUCCESS;
		return sentinel.ai_next;
	}

	h_errno = NO_RECOVERY;
	return NULL;
}

/*ARGSUSED*/
static int
_dns_getaddrinfo(rv, cb_data, ap)
	void	*rv;
	void	*cb_data;
	va_list	 ap;
{
	struct addrinfo *ai;
	querybuf *buf, *buf2, *bp;
	const char *name;
	const struct addrinfo *pai;
	struct addrinfo sentinel, *cur;
	struct res_target q, q2, *p;

	name = va_arg(ap, char *);
	pai = va_arg(ap, const struct addrinfo *);

	memset(&q, 0, sizeof(q2));
	memset(&q2, 0, sizeof(q2));
	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;

	buf = malloc(sizeof(*buf));
	if (!buf) {
		h_errno = NETDB_INTERNAL;
		return NS_NOTFOUND;
	}
	buf2 = malloc(sizeof(*buf2));
	if (!buf2) {
		free(buf);
		h_errno = NETDB_INTERNAL;
		return NS_NOTFOUND;
	}

	switch (pai->ai_family) {
	case AF_UNSPEC:
		/* prefer IPv6 */
		q.name = name;
		q.qclass = C_IN;
		q.qtype = T_AAAA;
		q.answer = buf->buf;
		q.anslen = sizeof(buf->buf);
		q.next = &q2;
		q2.name = name;
		q2.qclass = C_IN;
		q2.qtype = T_A;
		q2.answer = buf2->buf;
		q2.anslen = sizeof(buf2->buf);
		break;
	case AF_INET:
		q.name = name;
		q.qclass = C_IN;
		q.qtype = T_A;
		q.answer = buf->buf;
		q.anslen = sizeof(buf->buf);
		break;
	case AF_INET6:
		q.name = name;
		q.qclass = C_IN;
		q.qtype = T_AAAA;
		q.answer = buf->buf;
		q.anslen = sizeof(buf->buf);
		break;
	default:
		free(buf);
		free(buf2);
		return NS_UNAVAIL;
	}
	if (res_searchN(name, &q) < 0) {
		free(buf);
		free(buf2);
		return NS_NOTFOUND;
	}
	p = &q;
	while (p) {
		/* ugly... */
		if (p == &q)
			bp = buf;
		else if (p == &q2)
			bp = buf2;
		else {
			/* XXX should be abort() */
			p = p->next;
			continue;
		}

		ai = getanswer(bp, p->n, p->name, p->qtype, pai);
		if (ai) {
			cur->ai_next = ai;
			while (cur && cur->ai_next)
				cur = cur->ai_next;
		}
		p = p->next;
	}
	free(buf);
	free(buf2);
	if (sentinel.ai_next == NULL)
		switch (h_errno) {
		case HOST_NOT_FOUND:
			return NS_NOTFOUND;
		case TRY_AGAIN:
			return NS_TRYAGAIN;
		default:
			return NS_UNAVAIL;
		}
	*((struct addrinfo **)rv) = sentinel.ai_next;
	return NS_SUCCESS;
}

static void
_sethtent()
{

	if (!hostf)
		hostf = fopen(_PATH_HOSTS, "r" );
	else
		rewind(hostf);
}

static void
_endhtent()
{

	if (hostf) {
		(void) fclose(hostf);
		hostf = NULL;
	}
}

static struct addrinfo *
_gethtent(name, pai)
	const char *name;
	const struct addrinfo *pai;
{
	char *p;
	char *cp, *tname, *cname;
	struct addrinfo hints, *res0, *res;
	int error;
	const char *addr;
	char hostbuf[8*1024];

	if (!hostf && !(hostf = fopen(_PATH_HOSTS, "r" )))
		return (NULL);
again:
	if (!(p = fgets(hostbuf, sizeof hostbuf, hostf)))
		return (NULL);
	if (*p == '#')
		goto again;
	if (!(cp = strpbrk(p, "#\n")))
		goto again;
	*cp = '\0';
	if (!(cp = strpbrk(p, " \t")))
		goto again;
	*cp++ = '\0';
	addr = p;
	/* if this is not something we're looking for, skip it. */
	cname = NULL;
	while (cp && *cp) {
		if (*cp == ' ' || *cp == '\t') {
			cp++;
			continue;
		}
		if (!cname)
			cname = cp;
		tname = cp;
		if ((cp = strpbrk(cp, " \t")) != NULL)
			*cp++ = '\0';
		if (strcasecmp(name, tname) == 0)
			goto found;
	}
	goto again;

found:
	/* we should not glob socktype/protocol here */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = pai->ai_family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_NUMERICHOST;
	error = getaddrinfo(addr, "0", &hints, &res0);
	if (error)
		goto again;
#ifdef FILTER_V4MAPPED
	/* XXX should check all items in the chain */
	if (res0->ai_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)res0->ai_addr)->sin6_addr)) {
		freeaddrinfo(res0);
		goto again;
	}
#endif
	for (res = res0; res; res = res->ai_next) {
		/* cover it up */
		res->ai_flags = pai->ai_flags;
		res->ai_socktype = pai->ai_socktype;
		res->ai_protocol = pai->ai_protocol;

		if (pai->ai_flags & AI_CANONNAME) {
			if (get_canonname(pai, res, cname) != 0) {
				freeaddrinfo(res0);
				goto again;
			}
		}
	}
	return res0;
}

/*ARGSUSED*/
static int
_files_getaddrinfo(rv, cb_data, ap)
	void	*rv;
	void	*cb_data;
	va_list	 ap;
{
	const char *name;
	const struct addrinfo *pai;
	struct addrinfo sentinel, *cur;
	struct addrinfo *p;

	name = va_arg(ap, char *);
	pai = va_arg(ap, struct addrinfo *);

	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;

	_sethtent();
	while ((p = _gethtent(name, pai)) != NULL) {
		cur->ai_next = p;
		while (cur && cur->ai_next)
			cur = cur->ai_next;
	}
	_endhtent();

	*((struct addrinfo **)rv) = sentinel.ai_next;
	if (sentinel.ai_next == NULL)
		return NS_NOTFOUND;
	return NS_SUCCESS;
}

#ifdef YP
static char *__ypdomain;

/*ARGSUSED*/
static struct addrinfo *
_yphostent(line, pai)
	char *line;
	const struct addrinfo *pai;
{
	struct addrinfo sentinel, *cur;
	struct addrinfo hints, *res, *res0;
	int error;
	char *p = line;
	const char *addr, *canonname;
	char *nextline;
	char *cp;

	addr = canonname = NULL;

	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;

nextline:
	/* terminate line */
	cp = strchr(p, '\n');
	if (cp) {
		*cp++ = '\0';
		nextline = cp;
	} else
		nextline = NULL;

	cp = strpbrk(p, " \t");
	if (cp == NULL) {
		if (canonname == NULL)
			return (NULL);
		else
			goto done;
	}
	*cp++ = '\0';

	addr = p;

	while (cp && *cp) {
		if (*cp == ' ' || *cp == '\t') {
			cp++;
			continue;
		}
		if (!canonname)
			canonname = cp;
		if ((cp = strpbrk(cp, " \t")) != NULL)
			*cp++ = '\0';
	}

	/* we should not glob socktype/protocol here */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = pai->ai_family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_NUMERICHOST;
	error = getaddrinfo(addr, "0", &hints, &res0);
	if (error == 0) {
#ifdef FILTER_V4MAPPED
		/* XXX should check all items in the chain */
		if (res0->ai_family == AF_INET6 &&
		    IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)res0->ai_addr)->sin6_addr)) {
			freeaddrinfo(res0);
			res0 = NULL;
		}
#endif
		for (res = res0; res; res = res->ai_next) {
			/* cover it up */
			res->ai_flags = pai->ai_flags;
			res->ai_socktype = pai->ai_socktype;
			res->ai_protocol = pai->ai_protocol;

			if (pai->ai_flags & AI_CANONNAME)
				(void)get_canonname(pai, res, canonname);
		}
	} else
		res0 = NULL;
	if (res0) {
		cur->ai_next = res0;
		while (cur && cur->ai_next)
			cur = cur->ai_next;
	}

	if (nextline) {
		p = nextline;
		goto nextline;
	}

done:
	return sentinel.ai_next;
}

/*ARGSUSED*/
static int
_yp_getaddrinfo(rv, cb_data, ap)
	void	*rv;
	void	*cb_data;
	va_list	 ap;
{
	struct addrinfo sentinel, *cur;
	struct addrinfo *ai = NULL;
	static char *__ypcurrent;
	int __ypcurrentlen, r;
	const char *name;
	const struct addrinfo *pai;

	name = va_arg(ap, char *);
	pai = va_arg(ap, const struct addrinfo *);

	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;

	if (!__ypdomain) {
		if (_yp_check(&__ypdomain) == 0)
			return NS_UNAVAIL;
	}
	if (__ypcurrent)
		free(__ypcurrent);
	__ypcurrent = NULL;

	/* hosts.byname is only for IPv4 (Solaris8) */
	if (pai->ai_family == PF_UNSPEC || pai->ai_family == PF_INET) {
		r = yp_match(__ypdomain, "hosts.byname", name,
			(int)strlen(name), &__ypcurrent, &__ypcurrentlen);
		if (r == 0) {
			struct addrinfo ai4;

			ai4 = *pai;
			ai4.ai_family = AF_INET;
			ai = _yphostent(__ypcurrent, &ai4);
			if (ai) {
				cur->ai_next = ai;
				while (cur && cur->ai_next)
					cur = cur->ai_next;
			}
		}
	}

	/* ipnodes.byname can hold both IPv4/v6 */
	r = yp_match(__ypdomain, "ipnodes.byname", name,
		(int)strlen(name), &__ypcurrent, &__ypcurrentlen);
	if (r == 0) {
		ai = _yphostent(__ypcurrent, pai);
		if (ai) {
			cur->ai_next = ai;
			while (cur && cur->ai_next)
				cur = cur->ai_next;
		}
	}

	if (sentinel.ai_next == NULL) {
		h_errno = HOST_NOT_FOUND;
		return NS_NOTFOUND;
	}
	*((struct addrinfo **)rv) = sentinel.ai_next;
	return NS_SUCCESS;
}
#endif

/* resolver logic */

extern const char *__hostalias __P((const char *));
extern int h_errno;
#ifdef RES_USE_EDNS0
extern int res_opt __P((int, u_char *, int, int));
#endif

/*
 * Formulate a normal query, send, and await answer.
 * Returned answer is placed in supplied buffer "answer".
 * Perform preliminary check of answer, returning success only
 * if no error is indicated and the answer count is nonzero.
 * Return the size of the response on success, -1 on error.
 * Error number is left in h_errno.
 *
 * Caller must parse answer and determine whether it answers the question.
 */
static int
res_queryN(name, target)
	const char *name;	/* domain name */
	struct res_target *target;
{
	u_char buf[MAXPACKET];
	HEADER *hp;
	int n;
	struct res_target *t;
	int rcode;
	int ancount;

	rcode = NOERROR;
	ancount = 0;

	if ((_res.options & RES_INIT) == 0 && res_init() == -1) {
		h_errno = NETDB_INTERNAL;
		return (-1);
	}

	for (t = target; t; t = t->next) {
		int class, type;
		u_char *answer;
		int anslen;

		hp = (HEADER *)(void *)t->answer;
		hp->rcode = NOERROR;	/* default */

		/* make it easier... */
		class = t->qclass;
		type = t->qtype;
		answer = t->answer;
		anslen = t->anslen;
#ifdef DEBUG
		if (_res.options & RES_DEBUG)
			printf(";; res_query(%s, %d, %d)\n", name, class, type);
#endif

		n = res_mkquery(QUERY, name, class, type, NULL, 0, NULL,
		    buf, sizeof(buf));
#ifdef RES_USE_EDNS0
		if (n > 0 && (_res.options & RES_USE_EDNS0) != 0)
			n = res_opt(n, buf, sizeof(buf), anslen);
#endif
		if (n <= 0) {
#ifdef DEBUG
			if (_res.options & RES_DEBUG)
				printf(";; res_query: mkquery failed\n");
#endif
			h_errno = NO_RECOVERY;
			return (n);
		}
		n = res_send(buf, n, answer, anslen);
#if 0
		if (n < 0) {
#ifdef DEBUG
			if (_res.options & RES_DEBUG)
				printf(";; res_query: send error\n");
#endif
			h_errno = TRY_AGAIN;
			return (n);
		}
#endif

		if (n < 0 || hp->rcode != NOERROR || ntohs(hp->ancount) == 0) {
			rcode = hp->rcode;	/* record most recent error */
#ifdef DEBUG
			if (_res.options & RES_DEBUG)
				printf(";; rcode = %u, ancount=%u\n", hp->rcode,
				    ntohs(hp->ancount));
#endif
			continue;
		}

		ancount += ntohs(hp->ancount);

		t->n = n;
	}

	if (ancount == 0) {
		switch (rcode) {
		case NXDOMAIN:
			h_errno = HOST_NOT_FOUND;
			break;
		case SERVFAIL:
			h_errno = TRY_AGAIN;
			break;
		case NOERROR:
			h_errno = NO_DATA;
			break;
		case FORMERR:
		case NOTIMP:
		case REFUSED:
		default:
			h_errno = NO_RECOVERY;
			break;
		}
		return (-1);
	}
	return (ancount);
}

/*
 * Formulate a normal query, send, and retrieve answer in supplied buffer.
 * Return the size of the response on success, -1 on error.
 * If enabled, implement search rules until answer or unrecoverable failure
 * is detected.  Error code, if any, is left in h_errno.
 */
static int
res_searchN(name, target)
	const char *name;	/* domain name */
	struct res_target *target;
{
	const char *cp, * const *domain;
	HEADER *hp = (HEADER *)(void *)target->answer;	/*XXX*/
	u_int dots;
	int trailing_dot, ret, saved_herrno;
	int got_nodata = 0, got_servfail = 0, tried_as_is = 0;

	if ((_res.options & RES_INIT) == 0 && res_init() == -1) {
		h_errno = NETDB_INTERNAL;
		return (-1);
	}

	errno = 0;
	h_errno = HOST_NOT_FOUND;	/* default, if we never query */
	dots = 0;
	for (cp = name; *cp; cp++)
		dots += (*cp == '.');
	trailing_dot = 0;
	if (cp > name && *--cp == '.')
		trailing_dot++;

	/*
	 * if there aren't any dots, it could be a user-level alias
	 */
	if (!dots && (cp = __hostalias(name)) != NULL)
		return (res_queryN(cp, target));

	/*
	 * If there are dots in the name already, let's just give it a try
	 * 'as is'.  The threshold can be set with the "ndots" option.
	 */
	saved_herrno = -1;
	if (dots >= _res.ndots) {
		ret = res_querydomainN(name, NULL, target);
		if (ret > 0)
			return (ret);
		saved_herrno = h_errno;
		tried_as_is++;
	}

	/*
	 * We do at least one level of search if
	 *	- there is no dot and RES_DEFNAME is set, or
	 *	- there is at least one dot, there is no trailing dot,
	 *	  and RES_DNSRCH is set.
	 */
	if ((!dots && (_res.options & RES_DEFNAMES)) ||
	    (dots && !trailing_dot && (_res.options & RES_DNSRCH))) {
		int done = 0;

		for (domain = (const char * const *)_res.dnsrch;
		   *domain && !done;
		   domain++) {

			ret = res_querydomainN(name, *domain, target);
			if (ret > 0)
				return (ret);

			/*
			 * If no server present, give up.
			 * If name isn't found in this domain,
			 * keep trying higher domains in the search list
			 * (if that's enabled).
			 * On a NO_DATA error, keep trying, otherwise
			 * a wildcard entry of another type could keep us
			 * from finding this entry higher in the domain.
			 * If we get some other error (negative answer or
			 * server failure), then stop searching up,
			 * but try the input name below in case it's
			 * fully-qualified.
			 */
			if (errno == ECONNREFUSED) {
				h_errno = TRY_AGAIN;
				return (-1);
			}

			switch (h_errno) {
			case NO_DATA:
				got_nodata++;
				/* FALLTHROUGH */
			case HOST_NOT_FOUND:
				/* keep trying */
				break;
			case TRY_AGAIN:
				if (hp->rcode == SERVFAIL) {
					/* try next search element, if any */
					got_servfail++;
					break;
				}
				/* FALLTHROUGH */
			default:
				/* anything else implies that we're done */
				done++;
			}
			/*
			 * if we got here for some reason other than DNSRCH,
			 * we only wanted one iteration of the loop, so stop.
			 */
			if (!(_res.options & RES_DNSRCH))
			        done++;
		}
	}

	/*
	 * if we have not already tried the name "as is", do that now.
	 * note that we do this regardless of how many dots were in the
	 * name or whether it ends with a dot.
	 */
	if (!tried_as_is) {
		ret = res_querydomainN(name, NULL, target);
		if (ret > 0)
			return (ret);
	}

	/*
	 * if we got here, we didn't satisfy the search.
	 * if we did an initial full query, return that query's h_errno
	 * (note that we wouldn't be here if that query had succeeded).
	 * else if we ever got a nodata, send that back as the reason.
	 * else send back meaningless h_errno, that being the one from
	 * the last DNSRCH we did.
	 */
	if (saved_herrno != -1)
		h_errno = saved_herrno;
	else if (got_nodata)
		h_errno = NO_DATA;
	else if (got_servfail)
		h_errno = TRY_AGAIN;
	return (-1);
}

/*
 * Perform a call on res_query on the concatenation of name and domain,
 * removing a trailing dot from name if domain is NULL.
 */
static int
res_querydomainN(name, domain, target)
	const char *name, *domain;
	struct res_target *target;
{
	char nbuf[MAXDNAME];
	const char *longname = nbuf;
	size_t n, d;

	if ((_res.options & RES_INIT) == 0 && res_init() == -1) {
		h_errno = NETDB_INTERNAL;
		return (-1);
	}
#ifdef DEBUG
	if (_res.options & RES_DEBUG)
		printf(";; res_querydomain(%s, %s)\n",
			name, domain?domain:"<Nil>");
#endif
	if (domain == NULL) {
		/*
		 * Check for trailing '.';
		 * copy without '.' if present.
		 */
		n = strlen(name);
		if (n >= MAXDNAME) {
			h_errno = NO_RECOVERY;
			return (-1);
		}
		if (n > 0 && name[--n] == '.') {
			strncpy(nbuf, name, n);
			nbuf[n] = '\0';
		} else
			longname = name;
	} else {
		n = strlen(name);
		d = strlen(domain);
		if (n + d + 1 >= MAXDNAME) {
			h_errno = NO_RECOVERY;
			return (-1);
		}
		snprintf(nbuf, sizeof(nbuf), "%s.%s", name, domain);
	}
	return (res_queryN(longname, target));
}

#elif defined(__OpenBSD__)

#include <syslog.h>
#include <stdarg.h>

#ifdef YP
#include <rpc/rpc.h>
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>
#endif

static void _sethtent __P((void));
static void _endhtent __P((void));
static struct addrinfo * _gethtent __P((const char *, const struct addrinfo *));
static struct addrinfo *_files_getaddrinfo __P((const char *,
	const struct addrinfo *));

#ifdef YP
static struct addrinfo *_yphostent __P((char *, const struct addrinfo *));
static struct addrinfo *_yp_getaddrinfo __P((const char *,
	const struct addrinfo *));
#endif

static struct addrinfo *getanswer __P((const querybuf *, int, const char *,
	int, const struct addrinfo *));

static int res_queryN __P((const char *, struct res_target *));
static int res_searchN __P((const char *, struct res_target *));
static int res_querydomainN __P((const char *, const char *,
	struct res_target *));
static struct addrinfo *_dns_getaddrinfo __P((const char *,
	const struct addrinfo *));

#ifdef __OpenBSD__
_THREAD_PRIVATE_MUTEX(getaddrinfo_explore_fqdn);
#endif

/*
 * FQDN hostname, DNS lookup
 */
static int
explore_fqdn(pai, hostname, servname, res)
	const struct addrinfo *pai;
	const char *hostname;
	const char *servname;
	struct addrinfo **res;
{
	struct addrinfo *result;
	struct addrinfo *cur;
	int error = 0;
	char lookups[MAXDNSLUS];
	int i;

#ifdef __OpenBSD__
	_THREAD_PRIVATE_MUTEX_LOCK(getaddrinfo_explore_fqdn);
#endif

	result = NULL;

	/*
	 * if the servname does not match socktype/protocol, ignore it.
	 */
	if (get_portmatch(pai, servname) != 0) {
#ifdef __OpenBSD__
		_THREAD_PRIVATE_MUTEX_UNLOCK(getaddrinfo_explore_fqdn);
#endif
		return 0;
	}

	if ((_res.options & RES_INIT) == 0 && res_init() == -1)
		strncpy(lookups, "f", sizeof lookups);
	else {
		bcopy(_res.lookups, lookups, sizeof lookups);
		if (lookups[0] == '\0')
			strncpy(lookups, "bf", sizeof lookups);
	}

	for (i = 0; i < MAXDNSLUS && result == NULL && lookups[i]; i++) {
		switch (lookups[i]) {
#ifdef YP
		case 'y':
			result = _yp_getaddrinfo(hostname, pai);
			break;
#endif
		case 'b':
			result = _dns_getaddrinfo(hostname, pai);
			break;
		case 'f':
			result = _files_getaddrinfo(hostname, pai);
			break;
		}
	}
	if (result) {
		for (cur = result; cur; cur = cur->ai_next) {
			GET_PORT(cur, servname);
			/* canonname should already be filled. */
		}
		*res = result;
#ifdef __OpenBSD__
		_THREAD_PRIVATE_MUTEX_UNLOCK(getaddrinfo_explore_fqdn);
#endif
		return 0;
	} else {
		/* translate error code */
		switch (h_errno) {
		case NETDB_SUCCESS:
			error = EAI_FAIL;	/*XXX strange */
			break;
		case HOST_NOT_FOUND:
			error = EAI_NONAME;
			break;
		case TRY_AGAIN:
			error = EAI_AGAIN;
			break;
		case NO_RECOVERY:
			error = EAI_FAIL;
			break;
		case NO_DATA:
#if NO_ADDRESS != NO_DATA
		case NO_ADDRESS:
#endif
			error = EAI_NONAME;
			break;
		default:			/* unknown ones */
			error = EAI_FAIL;
			break;
		}
	}

free:
	if (result)
		freeaddrinfo(result);
#ifdef __OpenBSD__
	_THREAD_PRIVATE_MUTEX_UNLOCK(getaddrinfo_explore_fqdn);
#endif
	return error;
}

/* code duplicate with gethnamaddr.c */

static const char AskedForGot[] =
	"gethostby*.getanswer: asked for \"%s\", got \"%s\"";
static FILE *hostf = NULL;

static struct addrinfo *
getanswer(answer, anslen, qname, qtype, pai)
	const querybuf *answer;
	int anslen;
	const char *qname;
	int qtype;
	const struct addrinfo *pai;
{
	struct addrinfo sentinel, *cur;
	struct addrinfo ai;
	const struct afd *afd;
	char *canonname;
	const HEADER *hp;
	const u_char *cp;
	int n;
	const u_char *eom;
	char *bp, *ep;
	int type, class, ancount, qdcount;
	int haveanswer, had_error;
	char tbuf[MAXDNAME];
	int (*name_ok) __P((const char *));
	char hostbuf[8*1024];

	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;

	canonname = NULL;
	eom = answer->buf + anslen;
	switch (qtype) {
	case T_A:
	case T_AAAA:
	case T_ANY:	/*use T_ANY only for T_A/T_AAAA lookup*/
		name_ok = res_hnok;
		break;
	default:
		return (NULL);	/* XXX should be abort(); */
	}
	/*
	 * find first satisfactory answer
	 */
	hp = &answer->hdr;
	ancount = ntohs(hp->ancount);
	qdcount = ntohs(hp->qdcount);
	bp = hostbuf;
	ep = hostbuf + sizeof hostbuf;
	cp = answer->buf + HFIXEDSZ;
	if (qdcount != 1) {
		h_errno = NO_RECOVERY;
		return (NULL);
	}
	n = dn_expand(answer->buf, eom, cp, bp, ep - bp);
	if ((n < 0) || !(*name_ok)(bp)) {
		h_errno = NO_RECOVERY;
		return (NULL);
	}
	cp += n + QFIXEDSZ;
	if (qtype == T_A || qtype == T_AAAA || qtype == T_ANY) {
		/* res_send() has already verified that the query name is the
		 * same as the one we sent; this just gets the expanded name
		 * (i.e., with the succeeding search-domain tacked on).
		 */
		n = strlen(bp) + 1;		/* for the \0 */
		if (n >= MAXHOSTNAMELEN) {
			h_errno = NO_RECOVERY;
			return (NULL);
		}
		canonname = bp;
		bp += n;
		/* The qname can be abbreviated, but h_name is now absolute. */
		qname = canonname;
	}
	haveanswer = 0;
	had_error = 0;
	while (ancount-- > 0 && cp < eom && !had_error) {
		n = dn_expand(answer->buf, eom, cp, bp, ep - bp);
		if ((n < 0) || !(*name_ok)(bp)) {
			had_error++;
			continue;
		}
		cp += n;			/* name */
		type = _getshort(cp);
 		cp += INT16SZ;			/* type */
		class = _getshort(cp);
 		cp += INT16SZ + INT32SZ;	/* class, TTL */
		n = _getshort(cp);
		cp += INT16SZ;			/* len */
		if (class != C_IN) {
			/* XXX - debug? syslog? */
			cp += n;
			continue;		/* XXX - had_error++ ? */
		}
		if ((qtype == T_A || qtype == T_AAAA || qtype == T_ANY) &&
		    type == T_CNAME) {
			n = dn_expand(answer->buf, eom, cp, tbuf, sizeof tbuf);
			if ((n < 0) || !(*name_ok)(tbuf)) {
				had_error++;
				continue;
			}
			cp += n;
			/* Get canonical name. */
			n = strlen(tbuf) + 1;	/* for the \0 */
			if (n > ep - bp || n >= MAXHOSTNAMELEN) {
				had_error++;
				continue;
			}
			strlcpy(bp, tbuf, ep - bp);
			canonname = bp;
			bp += n;
			continue;
		}
		if (qtype == T_ANY) {
			if (!(type == T_A || type == T_AAAA)) {
				cp += n;
				continue;
			}
		} else if (type != qtype) {
			if (type != T_KEY && type != T_SIG)
				syslog(LOG_NOTICE|LOG_AUTH,
	       "gethostby*.getanswer: asked for \"%s %s %s\", got type \"%s\"",
				       qname, p_class(C_IN), p_type(qtype),
				       p_type(type));
			cp += n;
			continue;		/* XXX - had_error++ ? */
		}
		switch (type) {
		case T_A:
		case T_AAAA:
			if (strcasecmp(canonname, bp) != 0) {
				syslog(LOG_NOTICE|LOG_AUTH,
				       AskedForGot, canonname, bp);
				cp += n;
				continue;	/* XXX - had_error++ ? */
			}
			if (type == T_A && n != INADDRSZ) {
				cp += n;
				continue;
			}
			if (type == T_AAAA && n != IN6ADDRSZ) {
				cp += n;
				continue;
			}
#ifdef FILTER_V4MAPPED
			if (type == T_AAAA) {
				struct in6_addr in6;
				memcpy(&in6, cp, sizeof(in6));
				if (IN6_IS_ADDR_V4MAPPED(&in6)) {
					cp += n;
					continue;
				}
			}
#endif
			if (!haveanswer) {
				int nn;

				canonname = bp;
				nn = strlen(bp) + 1;	/* for the \0 */
				bp += nn;
			}

			/* don't overwrite pai */
			ai = *pai;
			ai.ai_family = (type == T_A) ? AF_INET : AF_INET6;
			afd = find_afd(ai.ai_family);
			if (afd == NULL) {
				cp += n;
				continue;
			}
			cur->ai_next = get_ai(&ai, afd, (const char *)cp);
			if (cur->ai_next == NULL)
				had_error++;
			while (cur && cur->ai_next)
				cur = cur->ai_next;
			cp += n;
			break;
		default:
			abort();
		}
		if (!had_error)
			haveanswer++;
	}
	if (haveanswer) {
		if (!canonname)
			(void)get_canonname(pai, sentinel.ai_next, qname);
		else
			(void)get_canonname(pai, sentinel.ai_next, canonname);
		h_errno = NETDB_SUCCESS;
		return sentinel.ai_next;
	}

	h_errno = NO_RECOVERY;
	return NULL;
}

/*ARGSUSED*/
static struct addrinfo *
_dns_getaddrinfo(name, pai)
	const char *name;
	const struct addrinfo *pai;
{
	struct addrinfo *ai;
	querybuf *buf, *buf2;
	struct addrinfo sentinel, *cur;
	struct res_target q, q2;

	memset(&q, 0, sizeof(q2));
	memset(&q2, 0, sizeof(q2));
	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;

	buf = malloc(sizeof(*buf));
	if (!buf) {
		h_errno = NETDB_INTERNAL;
		return NULL;
	}
	buf2 = malloc(sizeof(*buf2));
	if (!buf2) {
		free(buf);
		h_errno = NETDB_INTERNAL;
		return NULL;
	}

	switch (pai->ai_family) {
	case AF_UNSPEC:
		/* prefer IPv6 */
		q.name = name;
		q.qclass = C_IN;
		q.qtype = T_AAAA;
		q.answer = buf->buf;
		q.anslen = sizeof(buf->buf);
		q.next = &q2;
		q2.name = name;
		q2.qclass = C_IN;
		q2.qtype = T_A;
		q2.answer = buf2->buf;
		q2.anslen = sizeof(buf2->buf);
		break;
	case AF_INET:
		q.name = name;
		q.qclass = C_IN;
		q.qtype = T_A;
		q.answer = buf->buf;
		q.anslen = sizeof(buf->buf);
		break;
	case AF_INET6:
		q.name = name;
		q.qclass = C_IN;
		q.qtype = T_AAAA;
		q.answer = buf->buf;
		q.anslen = sizeof(buf->buf);
		break;
	default:
		free(buf);
		free(buf2);
		return NULL;
	}
	if (res_searchN(name, &q) < 0) {
		free(buf);
		free(buf2);
		return NULL;
	}
	ai = getanswer(buf, q.n, q.name, q.qtype, pai);
	if (ai) {
		cur->ai_next = ai;
		while (cur && cur->ai_next)
			cur = cur->ai_next;
	}
	if (q.next) {
		ai = getanswer(buf2, q2.n, q2.name, q2.qtype, pai);
		if (ai)
			cur->ai_next = ai;
	}
	free(buf);
	free(buf2);
	return sentinel.ai_next;
}

static FILE *hostf;

static void
_sethtent()
{
	if (!hostf)
		hostf = fopen(_PATH_HOSTS, "r" );
	else
		rewind(hostf);
}

static void
_endhtent()
{
	if (hostf) {
		(void) fclose(hostf);
		hostf = NULL;
	}
}

static struct addrinfo *
_gethtent(name, pai)
	const char *name;
	const struct addrinfo *pai;
{
	char *p;
	char *cp, *tname, *cname;
	struct addrinfo hints, *res0, *res;
	int error;
	const char *addr;
	char hostbuf[8*1024];

	if (!hostf && !(hostf = fopen(_PATH_HOSTS, "r" )))
		return (NULL);
again:
	if (!(p = fgets(hostbuf, sizeof hostbuf, hostf)))
		return (NULL);
	if (*p == '#')
		goto again;
	if (!(cp = strpbrk(p, "#\n")))
		goto again;
	*cp = '\0';
	if (!(cp = strpbrk(p, " \t")))
		goto again;
	*cp++ = '\0';
	addr = p;
	/* if this is not something we're looking for, skip it. */
	cname = NULL;
	while (cp && *cp) {
		if (*cp == ' ' || *cp == '\t') {
			cp++;
			continue;
		}
		if (!cname)
			cname = cp;
		tname = cp;
		if ((cp = strpbrk(cp, " \t")) != NULL)
			*cp++ = '\0';
		if (strcasecmp(name, tname) == 0)
			goto found;
	}
	goto again;

found:
	/* we should not glob socktype/protocol here */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = pai->ai_family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_NUMERICHOST;
	error = getaddrinfo(addr, "0", &hints, &res0);
	if (error)
		goto again;
#ifdef FILTER_V4MAPPED
	/* XXX should check all items in the chain */
	if (res0->ai_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)res0->ai_addr)->sin6_addr)) {
		freeaddrinfo(res0);
		goto again;
	}
#endif
	for (res = res0; res; res = res->ai_next) {
		/* cover it up */
		res->ai_flags = pai->ai_flags;
		res->ai_socktype = pai->ai_socktype;
		res->ai_protocol = pai->ai_protocol;

		if (pai->ai_flags & AI_CANONNAME) {
			if (get_canonname(pai, res, cname) != 0) {
				freeaddrinfo(res0);
				goto again;
			}
		}
	}
	return res0;
}

/*ARGSUSED*/
static struct addrinfo *
_files_getaddrinfo(name, pai)
	const char *name;
	const struct addrinfo *pai;
{
	struct addrinfo sentinel, *cur;
	struct addrinfo *p;

	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;

	_sethtent();
	while ((p = _gethtent(name, pai)) != NULL) {
		cur->ai_next = p;
		while (cur && cur->ai_next)
			cur = cur->ai_next;
	}
	_endhtent();

	return sentinel.ai_next;
}

#ifdef YP
static char *__ypdomain;

/*ARGSUSED*/
static struct addrinfo *
_yphostent(line, pai)
	char *line;
	const struct addrinfo *pai;
{
	struct addrinfo sentinel, *cur;
	struct addrinfo hints, *res, *res0;
	int error;
	char *p = line;
	const char *addr, *canonname;
	char *nextline;
	char *cp;

	addr = canonname = NULL;

	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;

nextline:
	/* terminate line */
	cp = strchr(p, '\n');
	if (cp) {
		*cp++ = '\0';
		nextline = cp;
	} else
		nextline = NULL;

	cp = strpbrk(p, " \t");
	if (cp == NULL) {
		if (canonname == NULL)
			return (NULL);
		else
			goto done;
	}
	*cp++ = '\0';

	addr = p;

	while (cp && *cp) {
		if (*cp == ' ' || *cp == '\t') {
			cp++;
			continue;
		}
		if (!canonname)
			canonname = cp;
		if ((cp = strpbrk(cp, " \t")) != NULL)
			*cp++ = '\0';
	}

	/* we should not glob socktype/protocol here */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = pai->ai_family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_NUMERICHOST;
	error = getaddrinfo(addr, "0", &hints, &res0);
	if (error == 0) {
#ifdef FILER_V4MAPPED
		/* XXX should check all items in the chain */
		if (res0->ai_family == AF_INET6 &&
		    IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)res0->ai_addr)->sin6_addr)) {
			freeaddrinfo(res0);
			res0 = NULL;
		}
#endif
		for (res = res0; res; res = res->ai_next) {
			/* cover it up */
			res->ai_flags = pai->ai_flags;
			res->ai_socktype = pai->ai_socktype;
			res->ai_protocol = pai->ai_protocol;

			if (pai->ai_flags & AI_CANONNAME)
				(void)get_canonname(pai, res, canonname);
		}
	} else
		res0 = NULL;
	if (res0) {
		cur->ai_next = res0;
		while (cur && cur->ai_next)
			cur = cur->ai_next;
	}

	if (nextline) {
		p = nextline;
		goto nextline;
	}

done:
	return sentinel.ai_next;
}

/*ARGSUSED*/
static struct addrinfo *
_yp_getaddrinfo(name, pai)
	const char *name;
	const struct addrinfo *pai;
{
	struct addrinfo sentinel, *cur;
	struct addrinfo *ai = NULL;
	static char *__ypcurrent;
	int __ypcurrentlen, r;

	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;

	if (!__ypdomain) {
		if (_yp_check(&__ypdomain) == 0)
			return NULL;
	}
	if (__ypcurrent)
		free(__ypcurrent);
	__ypcurrent = NULL;

	/* hosts.byname is only for IPv4 (Solaris8) */
	if (pai->ai_family == PF_UNSPEC || pai->ai_family == PF_INET) {
		r = yp_match(__ypdomain, "hosts.byname", name,
			(int)strlen(name), &__ypcurrent, &__ypcurrentlen);
		if (r == 0) {
			struct addrinfo ai4;

			ai4 = *pai;
			ai4.ai_family = AF_INET;
			ai = _yphostent(__ypcurrent, &ai4);
			if (ai) {
				cur->ai_next = ai;
				while (cur && cur->ai_next)
					cur = cur->ai_next;
			}
		}
	}

	/* ipnodes.byname can hold both IPv4/v6 */
	r = yp_match(__ypdomain, "ipnodes.byname", name,
		(int)strlen(name), &__ypcurrent, &__ypcurrentlen);
	if (r == 0) {
		ai = _yphostent(__ypcurrent, pai);
		if (ai) {
			cur->ai_next = ai;
			while (cur && cur->ai_next)
				cur = cur->ai_next;
		}
	}

	return sentinel.ai_next;
}
#endif


/* resolver logic */

extern const char *__hostalias __P((const char *));
extern int h_errno;
#ifdef RES_USE_EDNS0
extern int res_opt __P((int, u_char *, int, int));
#endif

/*
 * Formulate a normal query, send, and await answer.
 * Returned answer is placed in supplied buffer "answer".
 * Perform preliminary check of answer, returning success only
 * if no error is indicated and the answer count is nonzero.
 * Return the size of the response on success, -1 on error.
 * Error number is left in h_errno.
 *
 * Caller must parse answer and determine whether it answers the question.
 */
static int
res_queryN(name, target)
	const char *name;	/* domain name */
	struct res_target *target;
{
	u_char buf[MAXPACKET];
	HEADER *hp;
	int n;
	struct res_target *t;
	int rcode;
	int ancount;

	rcode = NOERROR;
	ancount = 0;

	if ((_res.options & RES_INIT) == 0 && res_init() == -1) {
		h_errno = NETDB_INTERNAL;
		return (-1);
	}

	for (t = target; t; t = t->next) {
		int class, type;
		u_char *answer;
		int anslen;

		hp = (HEADER *)(void *)t->answer;
		hp->rcode = NOERROR;	/* default */

		/* make it easier... */
		class = t->qclass;
		type = t->qtype;
		answer = t->answer;
		anslen = t->anslen;
#ifdef DEBUG
		if (_res.options & RES_DEBUG)
			printf(";; res_query(%s, %d, %d)\n", name, class, type);
#endif

		n = res_mkquery(QUERY, name, class, type, NULL, 0, NULL,
		    buf, sizeof(buf));
#ifdef RES_USE_EDNS0
		if (n > 0 && (_res.options & RES_USE_EDNS0) != 0)
			n = res_opt(n, buf, sizeof(buf), anslen);
#endif
		if (n <= 0) {
#ifdef DEBUG
			if (_res.options & RES_DEBUG)
				printf(";; res_query: mkquery failed\n");
#endif
			h_errno = NO_RECOVERY;
			return (n);
		}
		n = res_send(buf, n, answer, anslen);
#if 0
		if (n < 0) {
#ifdef DEBUG
			if (_res.options & RES_DEBUG)
				printf(";; res_query: send error\n");
#endif
			h_errno = TRY_AGAIN;
			return (n);
		}
#endif

		if (n < 0 || hp->rcode != NOERROR || ntohs(hp->ancount) == 0) {
			rcode = hp->rcode;	/* record most recent error */
#ifdef DEBUG
			if (_res.options & RES_DEBUG)
				printf(";; rcode = %u, ancount=%u\n", hp->rcode,
				    ntohs(hp->ancount));
#endif
			continue;
		}

		ancount += ntohs(hp->ancount);

		t->n = n;
	}

	if (ancount == 0) {
		switch (rcode) {
		case NXDOMAIN:
			h_errno = HOST_NOT_FOUND;
			break;
		case SERVFAIL:
			h_errno = TRY_AGAIN;
			break;
		case NOERROR:
			h_errno = NO_DATA;
			break;
		case FORMERR:
		case NOTIMP:
		case REFUSED:
		default:
			h_errno = NO_RECOVERY;
			break;
		}
		return (-1);
	}
	return (ancount);
}

/*
 * Formulate a normal query, send, and retrieve answer in supplied buffer.
 * Return the size of the response on success, -1 on error.
 * If enabled, implement search rules until answer or unrecoverable failure
 * is detected.  Error code, if any, is left in h_errno.
 */
static int
res_searchN(name, target)
	const char *name;	/* domain name */
	struct res_target *target;
{
	const char *cp, * const *domain;
	HEADER *hp = (HEADER *)(void *)target->answer;	/*XXX*/
	u_int dots;
	int trailing_dot, ret, saved_herrno;
	int got_nodata = 0, got_servfail = 0, tried_as_is = 0;

	if ((_res.options & RES_INIT) == 0 && res_init() == -1) {
		h_errno = NETDB_INTERNAL;
		return (-1);
	}

	errno = 0;
	h_errno = HOST_NOT_FOUND;	/* default, if we never query */
	dots = 0;
	for (cp = name; *cp; cp++)
		dots += (*cp == '.');
	trailing_dot = 0;
	if (cp > name && *--cp == '.')
		trailing_dot++;

	/*
	 * if there aren't any dots, it could be a user-level alias
	 */
	if (!dots && (cp = __hostalias(name)) != NULL)
		return (res_queryN(cp, target));

	/*
	 * If there are dots in the name already, let's just give it a try
	 * 'as is'.  The threshold can be set with the "ndots" option.
	 */
	saved_herrno = -1;
	if (dots >= _res.ndots) {
		ret = res_querydomainN(name, NULL, target);
		if (ret > 0)
			return (ret);
		saved_herrno = h_errno;
		tried_as_is++;
	}

	/*
	 * We do at least one level of search if
	 *	- there is no dot and RES_DEFNAME is set, or
	 *	- there is at least one dot, there is no trailing dot,
	 *	  and RES_DNSRCH is set.
	 */
	if ((!dots && (_res.options & RES_DEFNAMES)) ||
	    (dots && !trailing_dot && (_res.options & RES_DNSRCH))) {
		int done = 0;

		for (domain = (const char * const *)_res.dnsrch;
		   *domain && !done;
		   domain++) {

			ret = res_querydomainN(name, *domain, target);
			if (ret > 0)
				return (ret);

			/*
			 * If no server present, give up.
			 * If name isn't found in this domain,
			 * keep trying higher domains in the search list
			 * (if that's enabled).
			 * On a NO_DATA error, keep trying, otherwise
			 * a wildcard entry of another type could keep us
			 * from finding this entry higher in the domain.
			 * If we get some other error (negative answer or
			 * server failure), then stop searching up,
			 * but try the input name below in case it's
			 * fully-qualified.
			 */
			if (errno == ECONNREFUSED) {
				h_errno = TRY_AGAIN;
				return (-1);
			}

			switch (h_errno) {
			case NO_DATA:
				got_nodata++;
				/* FALLTHROUGH */
			case HOST_NOT_FOUND:
				/* keep trying */
				break;
			case TRY_AGAIN:
				if (hp->rcode == SERVFAIL) {
					/* try next search element, if any */
					got_servfail++;
					break;
				}
				/* FALLTHROUGH */
			default:
				/* anything else implies that we're done */
				done++;
			}
			/*
			 * if we got here for some reason other than DNSRCH,
			 * we only wanted one iteration of the loop, so stop.
			 */
			if (!(_res.options & RES_DNSRCH))
			        done++;
		}
	}

	/*
	 * if we have not already tried the name "as is", do that now.
	 * note that we do this regardless of how many dots were in the
	 * name or whether it ends with a dot.
	 */
	if (!tried_as_is) {
		ret = res_querydomainN(name, NULL, target);
		if (ret > 0)
			return (ret);
	}

	/*
	 * if we got here, we didn't satisfy the search.
	 * if we did an initial full query, return that query's h_errno
	 * (note that we wouldn't be here if that query had succeeded).
	 * else if we ever got a nodata, send that back as the reason.
	 * else send back meaningless h_errno, that being the one from
	 * the last DNSRCH we did.
	 */
	if (saved_herrno != -1)
		h_errno = saved_herrno;
	else if (got_nodata)
		h_errno = NO_DATA;
	else if (got_servfail)
		h_errno = TRY_AGAIN;
	return (-1);
}

/*
 * Perform a call on res_query on the concatenation of name and domain,
 * removing a trailing dot from name if domain is NULL.
 */
static int
res_querydomainN(name, domain, target)
	const char *name, *domain;
	struct res_target *target;
{
	char nbuf[MAXDNAME];
	const char *longname = nbuf;
	size_t n, d;

	if ((_res.options & RES_INIT) == 0 && res_init() == -1) {
		h_errno = NETDB_INTERNAL;
		return (-1);
	}
#ifdef DEBUG
	if (_res.options & RES_DEBUG)
		printf(";; res_querydomain(%s, %s)\n",
			name, domain?domain:"<Nil>");
#endif
	if (domain == NULL) {
		/*
		 * Check for trailing '.';
		 * copy without '.' if present.
		 */
		n = strlen(name);
		if (n >= MAXDNAME) {
			h_errno = NO_RECOVERY;
			return (-1);
		}
		if (n > 0 && name[--n] == '.') {
			strncpy(nbuf, name, n);
			nbuf[n] = '\0';
		} else
			longname = name;
	} else {
		n = strlen(name);
		d = strlen(domain);
		if (n + d + 1 >= MAXDNAME) {
			h_errno = NO_RECOVERY;
			return (-1);
		}
		snprintf(nbuf, sizeof(nbuf), "%s.%s", name, domain);
	}
	return (res_queryN(longname, target));
}

#elif defined(__bsdi__) && _BSDI_VERSION >= 199802

static struct net_data *init __P((void));

struct addrinfo *_hostent2addrinfo __P((struct hostent *,
				       const struct addrinfo *));
struct addrinfo *_addr2addrinfo __P((const struct addrinfo *,
				    const char *));

/*
 * FQDN hostname, DNS lookup
 */
static int
explore_fqdn(pai, hostname, servname, res)
	const struct addrinfo *pai;
	const char *hostname;
	const char *servname;
	struct addrinfo **res;
{
	struct addrinfo *result;
	struct addrinfo *cur;
	struct net_data *net_data = init();
	struct irs_ho *ho;
	int error = 0;
	char tmp[NS_MAXDNAME];
	const char *cp;

	result = NULL;

	/*
	 * if the servname does not match socktype/protocol, ignore it.
	 */
	if (get_portmatch(pai, servname) != 0)
		return(0);

	if (!net_data || !(ho = net_data->ho))
		return(0);
#if 0				/* XXX (notyet) */
	if (net_data->ho_stayopen && net_data->ho_last &&
	    net_data->ho_last->h_addrtype == af) {
		if (ns_samename(name, net_data->ho_last->h_name) == 1)
			return (net_data->ho_last);
		for (hap = net_data->ho_last->h_aliases; hap && *hap; hap++)
			if (ns_samename(name, *hap) == 1)
				return (net_data->ho_last);
	}
#endif
	if (!strchr(hostname, '.') &&
	    (cp = res_hostalias(net_data->res, hostname,
				tmp, sizeof(tmp))))
		hostname = cp;
	result = (*ho->addrinfo)(ho, hostname, pai);
	if (!net_data->ho_stayopen) {
		(*ho->minimize)(ho);
	}
	if (result == NULL) {
		int *e = __h_errno();

		switch(*e) {
		case NETDB_INTERNAL:
			error = EAI_SYSTEM;
			break;
		case TRY_AGAIN:
			error = EAI_AGAIN;
			break;
		case NO_RECOVERY:
			error = EAI_FAIL;
			break;
		case HOST_NOT_FOUND:
		case NO_DATA:
			error = EAI_NONAME;
			break;
		default:
		case NETDB_SUCCESS: /* should be impossible... */
			error = EAI_NONAME;
			break;
		}
		goto free;
	}

	for (cur = result; cur; cur = cur->ai_next) {
		GET_PORT(cur, servname); /* XXX: redundant lookups... */
		/* canonname should already be filled. */
	}

	*res = result;

	return(0);

free:
	if (result)
		freeaddrinfo(result);
	return error;
}

struct addrinfo *
_hostent2addrinfo(hp, pai)
	struct hostent *hp;
	const struct addrinfo *pai;
{
	int i, af, error = 0;
	char **aplist = NULL, *ap;
	struct addrinfo sentinel, *cur;
	const struct afd *afd;

	af = hp->h_addrtype;
	if (pai->ai_family != AF_UNSPEC && af != pai->ai_family)
		return(NULL);

	afd = find_afd(af);
	if (afd == NULL)
		return(NULL);

	aplist = hp->h_addr_list;

	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;

	for (i = 0; (ap = aplist[i]) != NULL; i++) {
#if 0				/* the trick seems too much */
#ifdef INET6
		af = hp->h_addr_list;
		if (af == AF_INET6 &&
		    IN6_IS_ADDR_V4MAPPED((struct in6_addr *)ap)) {
			af = AF_INET;
			ap = ap + sizeof(struct in6_addr)
				- sizeof(struct in_addr);
		}
		afd = find_afd(af);
		if (afd == NULL)
			continue;
#endif
#endif /* 0 */

		GET_AI(cur->ai_next, afd, ap);

		/* GET_PORT(cur->ai_next, servname); */
		if ((pai->ai_flags & AI_CANONNAME) != 0) {
			/*
			 * RFC2553 says that ai_canonname will be set only for
			 * the first element.  we do it for all the elements,
			 * just for convenience.
			 */
			GET_CANONNAME(cur->ai_next, hp->h_name);
		}
		while (cur && cur->ai_next) /* no need to loop, actually. */
			cur = cur->ai_next;
		continue;

	free:
		if (cur->ai_next)
			freeaddrinfo(cur->ai_next);
		cur->ai_next = NULL;
		/* continue, without tht pointer CUR advanced. */
	}

	return(sentinel.ai_next);
}

struct addrinfo *
_addr2addrinfo(pai, cp)
	const struct addrinfo *pai;
	const char *cp;
{
	const struct afd *afd;

	afd = find_afd(pai->ai_family);
	if (afd == NULL)
		return(NULL);

	return(get_ai(pai, afd, cp));
}

static struct net_data *
init()
{
	struct net_data *net_data;

	if (!(net_data = net_data_init(NULL)))
		goto error;
	if (!net_data->ho) {
		net_data->ho = (*net_data->irs->ho_map)(net_data->irs);
		if (!net_data->ho || !net_data->res) {
error:
			errno = EIO;
			if (net_data && net_data->res)
				RES_SET_H_ERRNO(net_data->res, NETDB_INTERNAL);
			return (NULL);
		}

		(*net_data->ho->res_set)(net_data->ho, net_data->res, NULL);
	}

	return (net_data);
}

#elif defined(__FreeBSD__) && __FreeBSD__ >= 4

static struct addrinfo *getanswer __P((const querybuf *, int, const char *,
	int, const struct addrinfo *));

static int _dns_getaddrinfo __P((const struct addrinfo *, const char *,
	struct addrinfo **));
static struct addrinfo *_gethtent __P((FILE *fp, const char *,
	const struct addrinfo *));
static int _files_getaddrinfo __P((const struct addrinfo *, const char *,
	struct addrinfo **));
#ifdef YP
static int _nis_getaddrinfo __P((const struct addrinfo *, const char *,
	 struct addrinfo **));
#endif

static int res_queryN __P((const char *, struct res_target *));
static int res_searchN __P((const char *, struct res_target *));
static int res_querydomainN __P((const char *, const char *,
	struct res_target *));

/*
 * Select order host function.
 */
#define MAXHOSTCONF	4

#ifndef HOSTCONF
#  define	HOSTCONF	"/etc/host.conf"
#endif /* !HOSTCONF */

struct _hostconf {
	int (*byname)(const struct addrinfo *, const char *,
		      struct addrinfo **);
};

/* default order */
static struct _hostconf _hostconf[MAXHOSTCONF] = {
	_dns_getaddrinfo,
	_files_getaddrinfo,
#ifdef ICMPNL
	NULL,
#endif /* ICMPNL */
};

static int	_hostconf_init_done;
static void	_hostconf_init(void);

/*
 * FQDN hostname, DNS lookup
 */
static int
explore_fqdn(pai, hostname, servname, res)
	const struct addrinfo *pai;
	const char *hostname;
	const char *servname;
	struct addrinfo **res;
{
	struct addrinfo *result;
	struct addrinfo *cur;
	int error = 0, i;

	result = NULL;
	*res = NULL;

	/*
	 * if the servname does not match socktype/protocol, ignore it.
	 */
	if (get_portmatch(pai, servname) != 0)
		return 0;

	if (!_hostconf_init_done)
		_hostconf_init();

	for (i = 0; i < MAXHOSTCONF; i++) {
		if (!_hostconf[i].byname)
			continue;
		error = (*_hostconf[i].byname)(pai, hostname, &result);
		if (error != 0)
			continue;
		for (cur = result; cur; cur = cur->ai_next) {
			GET_PORT(cur, servname);
			/* canonname should already be filled. */
		}
		*res = result;
		return 0;
	}

free:
	if (result)
		freeaddrinfo(result);
	return error;
}

static char *
_hgetword(char **pp)
{
	char c, *p, *ret;
	const char *sp;
	static const char sep[] = "# \t\n";

	ret = NULL;
	for (p = *pp; (c = *p) != '\0'; p++) {
		for (sp = sep; *sp != '\0'; sp++) {
			if (c == *sp)
				break;
		}
		if (c == '#')
			p[1] = '\0';	/* ignore rest of line */
		if (ret == NULL) {
			if (*sp == '\0')
				ret = p;
		} else {
			if (*sp != '\0') {
				*p++ = '\0';
				break;
			}
		}
	}
	*pp = p;
	if (ret == NULL || *ret == '\0')
		return NULL;
	return ret;
}

/*
 * Initialize hostconf structure.
 */

static void
_hostconf_init(void)
{
	FILE *fp;
	int n;
	char *p, *line;
	char buf[BUFSIZ];

	_hostconf_init_done = 1;
	n = 0;
	p = HOSTCONF;
	if ((fp = fopen(p, "r")) == NULL)
		return;
	while (n < MAXHOSTCONF && fgets(buf, sizeof(buf), fp)) {
		line = buf;
		if ((p = _hgetword(&line)) == NULL)
			continue;
		do {
			if (strcmp(p, "hosts") == 0
			||  strcmp(p, "local") == 0
			||  strcmp(p, "file") == 0
			||  strcmp(p, "files") == 0)
				_hostconf[n++].byname = _files_getaddrinfo;
			else if (strcmp(p, "dns") == 0
			     ||  strcmp(p, "bind") == 0)
				_hostconf[n++].byname = _dns_getaddrinfo;
#ifdef YP
			else if (strcmp(p, "nis") == 0)
				_hostconf[n++].byname = _nis_getaddrinfo;
#endif
		} while ((p = _hgetword(&line)) != NULL);
	}
	fclose(fp);
	if (n < 0) {
		/* no keyword found. do not change default configuration */
		return;
	}
	for (; n < MAXHOSTCONF; n++)
		_hostconf[n].byname = NULL;
}

#ifdef DEBUG
static const char AskedForGot[] =
	"gethostby*.getanswer: asked for \"%s\", got \"%s\"";
#endif

static struct addrinfo *
getanswer(answer, anslen, qname, qtype, pai)
	const querybuf *answer;
	int anslen;
	const char *qname;
	int qtype;
	const struct addrinfo *pai;
{
	struct addrinfo sentinel, *cur;
	struct addrinfo ai;
	const struct afd *afd;
	char *canonname;
	const HEADER *hp;
	const u_char *cp;
	int n;
	const u_char *eom;
	char *bp, *ep;
	int type, class, ancount, qdcount;
	int haveanswer, had_error;
	char tbuf[MAXDNAME];
	int (*name_ok) __P((const char *));
	char hostbuf[8*1024];

	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;

	canonname = NULL;
	eom = answer->buf + anslen;
	switch (qtype) {
	case T_A:
	case T_AAAA:
	case T_ANY:	/*use T_ANY only for T_A/T_AAAA lookup*/
		name_ok = res_hnok;
		break;
	default:
		return (NULL);	/* XXX should be abort(); */
	}
	/*
	 * find first satisfactory answer
	 */
	hp = &answer->hdr;
	ancount = ntohs(hp->ancount);
	qdcount = ntohs(hp->qdcount);
	bp = hostbuf;
	ep = hostbuf + sizeof hostbuf;
	cp = answer->buf + HFIXEDSZ;
	if (qdcount != 1) {
		h_errno = NO_RECOVERY;
		return (NULL);
	}
	n = dn_expand(answer->buf, eom, cp, bp, ep - bp);
	if ((n < 0) || !(*name_ok)(bp)) {
		h_errno = NO_RECOVERY;
		return (NULL);
	}
	cp += n + QFIXEDSZ;
	if (qtype == T_A || qtype == T_AAAA || qtype == T_ANY) {
		/* res_send() has already verified that the query name is the
		 * same as the one we sent; this just gets the expanded name
		 * (i.e., with the succeeding search-domain tacked on).
		 */
		n = strlen(bp) + 1;		/* for the \0 */
		if (n >= MAXHOSTNAMELEN) {
			h_errno = NO_RECOVERY;
			return (NULL);
		}
		canonname = bp;
		bp += n;
		/* The qname can be abbreviated, but h_name is now absolute. */
		qname = canonname;
	}
	haveanswer = 0;
	had_error = 0;
	while (ancount-- > 0 && cp < eom && !had_error) {
		n = dn_expand(answer->buf, eom, cp, bp, ep - bp);
		if ((n < 0) || !(*name_ok)(bp)) {
			had_error++;
			continue;
		}
		cp += n;			/* name */
		type = _getshort(cp);
 		cp += INT16SZ;			/* type */
		class = _getshort(cp);
 		cp += INT16SZ + INT32SZ;	/* class, TTL */
		n = _getshort(cp);
		cp += INT16SZ;			/* len */
		if (class != C_IN) {
			/* XXX - debug? syslog? */
			cp += n;
			continue;		/* XXX - had_error++ ? */
		}
		if ((qtype == T_A || qtype == T_AAAA || qtype == T_ANY) &&
		    type == T_CNAME) {
			n = dn_expand(answer->buf, eom, cp, tbuf, sizeof tbuf);
			if ((n < 0) || !(*name_ok)(tbuf)) {
				had_error++;
				continue;
			}
			cp += n;
			/* Get canonical name. */
			n = strlen(tbuf) + 1;	/* for the \0 */
			if (n > ep - bp || n >= MAXHOSTNAMELEN) {
				had_error++;
				continue;
			}
			strlcpy(bp, tbuf, ep - bp);
			canonname = bp;
			bp += n;
			continue;
		}
		if (qtype == T_ANY) {
			if (!(type == T_A || type == T_AAAA)) {
				cp += n;
				continue;
			}
		} else if (type != qtype) {
#ifdef DEBUG
			if (type != T_KEY && type != T_SIG)
				syslog(LOG_NOTICE|LOG_AUTH,
	       "gethostby*.getanswer: asked for \"%s %s %s\", got type \"%s\"",
				       qname, p_class(C_IN), p_type(qtype),
				       p_type(type));
#endif
			cp += n;
			continue;		/* XXX - had_error++ ? */
		}
		switch (type) {
		case T_A:
		case T_AAAA:
			if (strcasecmp(canonname, bp) != 0) {
#ifdef DEBUG
				syslog(LOG_NOTICE|LOG_AUTH,
				       AskedForGot, canonname, bp);
#endif
				cp += n;
				continue;	/* XXX - had_error++ ? */
			}
			if (type == T_A && n != INADDRSZ) {
				cp += n;
				continue;
			}
			if (type == T_AAAA && n != IN6ADDRSZ) {
				cp += n;
				continue;
			}
#ifdef FILTER_V4MAPPED
			if (type == T_AAAA) {
				struct in6_addr in6;
				memcpy(&in6, cp, sizeof(in6));
				if (IN6_IS_ADDR_V4MAPPED(&in6)) {
					cp += n;
					continue;
				}
			}
#endif
			if (!haveanswer) {
				int nn;

				canonname = bp;
				nn = strlen(bp) + 1;	/* for the \0 */
				bp += nn;
			}

			/* don't overwrite pai */
			ai = *pai;
			ai.ai_family = (type == T_A) ? AF_INET : AF_INET6;
			afd = find_afd(ai.ai_family);
			if (afd == NULL) {
				cp += n;
				continue;
			}
			cur->ai_next = get_ai(&ai, afd, (const char *)cp);
			if (cur->ai_next == NULL)
				had_error++;
			while (cur && cur->ai_next)
				cur = cur->ai_next;
			cp += n;
			break;
		default:
			abort();
		}
		if (!had_error)
			haveanswer++;
	}
	if (haveanswer) {
		if (!canonname)
			(void)get_canonname(pai, sentinel.ai_next, qname);
		else
			(void)get_canonname(pai, sentinel.ai_next, canonname);
		h_errno = NETDB_SUCCESS;
		return sentinel.ai_next;
	}

	h_errno = NO_RECOVERY;
	return NULL;
}

/*ARGSUSED*/
static int
_dns_getaddrinfo(pai, hostname, res)
	const struct addrinfo *pai;
	const char *hostname;
	struct addrinfo **res;
{
	struct addrinfo *ai;
	querybuf *buf, *buf2;
	const char *name;
	struct addrinfo sentinel, *cur;
	struct res_target q, q2;

	memset(&q, 0, sizeof(q2));
	memset(&q2, 0, sizeof(q2));
	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;

	buf = malloc(sizeof(*buf));
	if (!buf) {
		h_errno = NETDB_INTERNAL;
		return NULL;
	}
	buf2 = malloc(sizeof(*buf2));
	if (!buf2) {
		free(buf);
		h_errno = NETDB_INTERNAL;
		return NULL;
	}

	switch (pai->ai_family) {
	case AF_UNSPEC:
		/* prefer IPv6 */
		q.name = name;
		q.qclass = C_IN;
		q.qtype = T_AAAA;
		q.answer = buf->buf;
		q.anslen = sizeof(buf->buf);
		q.next = &q2;
		q2.name = name;
		q2.qclass = C_IN;
		q2.qtype = T_A;
		q2.answer = buf2->buf;
		q2.anslen = sizeof(buf2->buf);
		break;
	case AF_INET:
		q.name = name;
		q.qclass = C_IN;
		q.qtype = T_A;
		q.answer = buf->buf;
		q.anslen = sizeof(buf->buf);
		break;
	case AF_INET6:
		q.name = name;
		q.qclass = C_IN;
		q.qtype = T_AAAA;
		q.answer = buf->buf;
		q.anslen = sizeof(buf->buf);
		break;
	default:
		free(buf);
		free(buf2);
		return EAI_FAIL;
	}
	if (res_searchN(hostname, &q) < 0) {
		free(buf);
		free(buf2);
		return EAI_NONAME;
	}
	ai = getanswer(buf, q.n, q.name, q.qtype, pai);
	if (ai) {
		cur->ai_next = ai;
		while (cur && cur->ai_next)
			cur = cur->ai_next;
	}
	if (q.next) {
		ai = getanswer(buf2, q2.n, q2.name, q2.qtype, pai);
		if (ai)
			cur->ai_next = ai;
	}
	free(buf);
	free(buf2);
	if (sentinel.ai_next == NULL)
		switch (h_errno) {
		case HOST_NOT_FOUND:
			return EAI_NONAME;
		case TRY_AGAIN:
			return EAI_AGAIN;
		default:
			return EAI_FAIL;
		}
	*res = sentinel.ai_next;
	return 0;
}

static struct addrinfo *
_gethtent(hostf, name, pai)
	FILE *hostf;
	const char *name;
	const struct addrinfo *pai;
{
	char *p;
	char *cp, *tname, *cname;
	struct addrinfo hints, *res0, *res;
	int error;
	const char *addr;
	char hostbuf[8*1024];

again:
	if (!(p = fgets(hostbuf, sizeof hostbuf, hostf)))
		return (NULL);
	if (*p == '#')
		goto again;
	if (!(cp = strpbrk(p, "#\n")))
		goto again;
	*cp = '\0';
	if (!(cp = strpbrk(p, " \t")))
		goto again;
	*cp++ = '\0';
	addr = p;
	cname = NULL;
	/* if this is not something we're looking for, skip it. */
	while (cp && *cp) {
		if (*cp == ' ' || *cp == '\t') {
			cp++;
			continue;
		}
		tname = cp;
		if (cname == NULL)
			cname = cp;
		if ((cp = strpbrk(cp, " \t")) != NULL)
			*cp++ = '\0';
		if (strcasecmp(name, tname) == 0)
			goto found;
	}
	goto again;

found:
	/* we should not glob socktype/protocol here */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = pai->ai_family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_NUMERICHOST;
	error = getaddrinfo(addr, "0", &hints, &res0);
	if (error)
		goto again;
#ifdef FILTER_V4MAPPED
	/* XXX should check all items in the chain */
	if (res0->ai_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)res0->ai_addr)->sin6_addr)) {
		freeaddrinfo(res0);
		goto again;
	}
#endif
	for (res = res0; res; res = res->ai_next) {
		/* cover it up */
		res->ai_flags = pai->ai_flags;
		res->ai_socktype = pai->ai_socktype;
		res->ai_protocol = pai->ai_protocol;

		if (pai->ai_flags & AI_CANONNAME) {
			if (get_canonname(pai, res, cname) != 0) {
				freeaddrinfo(res0);
				goto again;
			}
		}
	}
	return res0;
}

/*ARGSUSED*/
static int
_files_getaddrinfo(pai, hostname, res)
	const struct addrinfo *pai;
	const char *hostname;
	struct addrinfo **res;
{
	FILE *hostf;
	struct addrinfo sentinel, *cur;
	struct addrinfo *p;

	sentinel.ai_next = NULL;
	cur = &sentinel;

	if ((hostf = fopen(_PATH_HOSTS, "r")) == NULL)
		return EAI_FAIL;
	while ((p = _gethtent(hostf, hostname, pai)) != NULL) {
		cur->ai_next = p;
		while (cur && cur->ai_next)
			cur = cur->ai_next;
	}
	fclose(hostf);

	if (!sentinel.ai_next)
		return EAI_NONAME;

	*res = sentinel.ai_next;
	return 0;
}

#ifdef YP
/*ARGSUSED*/
static int
_nis_getaddrinfo(pai, hostname, res)
	const struct addrinfo *pai;
	const char *hostname;
	struct addrinfo **res;
{
	struct hostent *hp;
	int h_error;
	int af;
	struct addrinfo sentinel, *cur;
	int i;
	const struct afd *afd;
	int error;

	sentinel.ai_next = NULL;
	cur = &sentinel;

	af = (pai->ai_family == AF_UNSPEC) ? AF_INET : pai->ai_family;
	if (af != AF_INET)
		return (EAI_FAMILY);

	if ((hp = _gethostbynisname(hostname, af)) == NULL) {
		switch (errno) {
		/* XXX: should be filled in */
		default:
			error = EAI_FAIL;
			break;
		}
	} else if (hp->h_name == NULL ||
		   hp->h_name[0] == 0 || hp->h_addr_list[0] == NULL) {
		hp = NULL;
		error = EAI_FAIL;
	}

	if (hp == NULL)
		return error;

	for (i = 0; hp->h_addr_list[i] != NULL; i++) {
		if (hp->h_addrtype != af)
			continue;

		afd = find_afd(hp->h_addrtype);
		if (afd == NULL)
			continue;

		GET_AI(cur->ai_next, afd, hp->h_addr_list[i]);
		if ((pai->ai_flags & AI_CANONNAME) != 0) {
			/*
			 * RFC2553 says that ai_canonname will be set only for
			 * the first element.  we do it for all the elements,
			 * just for convenience.
			 */
			GET_CANONNAME(cur->ai_next, hp->h_name);
		}

		while (cur && cur->ai_next)
			cur = cur->ai_next;
	}

	*res = sentinel.ai_next;
	return 0;

free:
	if (sentinel.ai_next)
		freeaddrinfo(sentinel.ai_next);
	return error;
}
#endif

/* resolver logic */

extern const char *__hostalias __P((const char *));
extern int h_errno;

/*
 * Formulate a normal query, send, and await answer.
 * Returned answer is placed in supplied buffer "answer".
 * Perform preliminary check of answer, returning success only
 * if no error is indicated and the answer count is nonzero.
 * Return the size of the response on success, -1 on error.
 * Error number is left in h_errno.
 *
 * Caller must parse answer and determine whether it answers the question.
 */
static int
res_queryN(name, target)
	const char *name;	/* domain name */
	struct res_target *target;
{
	u_char buf[MAXPACKET];
	HEADER *hp;
	int n;
	struct res_target *t;
	int rcode;
	int ancount;

	rcode = NOERROR;
	ancount = 0;

	if ((_res.options & RES_INIT) == 0 && res_init() == -1) {
		h_errno = NETDB_INTERNAL;
		return (-1);
	}

	for (t = target; t; t = t->next) {
		int class, type;
		u_char *answer;
		int anslen;

		hp = (HEADER *)(void *)t->answer;
		hp->rcode = NOERROR;	/* default */

		/* make it easier... */
		class = t->qclass;
		type = t->qtype;
		answer = t->answer;
		anslen = t->anslen;
#ifdef DEBUG
		if (_res.options & RES_DEBUG)
			printf(";; res_query(%s, %d, %d)\n", name, class, type);
#endif

		n = res_mkquery(QUERY, name, class, type, NULL, 0, NULL,
		    buf, sizeof(buf));
		if (n <= 0) {
#ifdef DEBUG
			if (_res.options & RES_DEBUG)
				printf(";; res_query: mkquery failed\n");
#endif
			h_errno = NO_RECOVERY;
			return (n);
		}
		n = res_send(buf, n, answer, anslen);
#if 0
		if (n < 0) {
#ifdef DEBUG
			if (_res.options & RES_DEBUG)
				printf(";; res_query: send error\n");
#endif
			h_errno = TRY_AGAIN;
			return (n);
		}
#endif

		if (n < 0 || hp->rcode != NOERROR || ntohs(hp->ancount) == 0) {
			rcode = hp->rcode;	/* record most recent error */
#ifdef DEBUG
			if (_res.options & RES_DEBUG)
				printf(";; rcode = %u, ancount=%u\n", hp->rcode,
				    ntohs(hp->ancount));
#endif
			continue;
		}

		ancount += ntohs(hp->ancount);

		t->n = n;
	}

	if (ancount == 0) {
		switch (rcode) {
		case NXDOMAIN:
			h_errno = HOST_NOT_FOUND;
			break;
		case SERVFAIL:
			h_errno = TRY_AGAIN;
			break;
		case NOERROR:
			h_errno = NO_DATA;
			break;
		case FORMERR:
		case NOTIMP:
		case REFUSED:
		default:
			h_errno = NO_RECOVERY;
			break;
		}
		return (-1);
	}
	return (ancount);
}

/*
 * Formulate a normal query, send, and retrieve answer in supplied buffer.
 * Return the size of the response on success, -1 on error.
 * If enabled, implement search rules until answer or unrecoverable failure
 * is detected.  Error code, if any, is left in h_errno.
 */
static int
res_searchN(name, target)
	const char *name;	/* domain name */
	struct res_target *target;
{
	const char *cp, * const *domain;
	HEADER *hp = (HEADER *)(void *)target->answer;	/*XXX*/
	u_int dots;
	int trailing_dot, ret, saved_herrno;
	int got_nodata = 0, got_servfail = 0, tried_as_is = 0;

	if ((_res.options & RES_INIT) == 0 && res_init() == -1) {
		h_errno = NETDB_INTERNAL;
		return (-1);
	}

	errno = 0;
	h_errno = HOST_NOT_FOUND;	/* default, if we never query */
	dots = 0;
	for (cp = name; *cp; cp++)
		dots += (*cp == '.');
	trailing_dot = 0;
	if (cp > name && *--cp == '.')
		trailing_dot++;

	/*
	 * if there aren't any dots, it could be a user-level alias
	 */
	if (!dots && (cp = __hostalias(name)) != NULL)
		return (res_queryN(cp, target));

	/*
	 * If there are dots in the name already, let's just give it a try
	 * 'as is'.  The threshold can be set with the "ndots" option.
	 */
	saved_herrno = -1;
	if (dots >= _res.ndots) {
		ret = res_querydomainN(name, NULL, target);
		if (ret > 0)
			return (ret);
		saved_herrno = h_errno;
		tried_as_is++;
	}

	/*
	 * We do at least one level of search if
	 *	- there is no dot and RES_DEFNAME is set, or
	 *	- there is at least one dot, there is no trailing dot,
	 *	  and RES_DNSRCH is set.
	 */
	if ((!dots && (_res.options & RES_DEFNAMES)) ||
	    (dots && !trailing_dot && (_res.options & RES_DNSRCH))) {
		int done = 0;

		for (domain = (const char * const *)_res.dnsrch;
		   *domain && !done;
		   domain++) {

			ret = res_querydomainN(name, *domain, target);
			if (ret > 0)
				return (ret);

			/*
			 * If no server present, give up.
			 * If name isn't found in this domain,
			 * keep trying higher domains in the search list
			 * (if that's enabled).
			 * On a NO_DATA error, keep trying, otherwise
			 * a wildcard entry of another type could keep us
			 * from finding this entry higher in the domain.
			 * If we get some other error (negative answer or
			 * server failure), then stop searching up,
			 * but try the input name below in case it's
			 * fully-qualified.
			 */
			if (errno == ECONNREFUSED) {
				h_errno = TRY_AGAIN;
				return (-1);
			}

			switch (h_errno) {
			case NO_DATA:
				got_nodata++;
				/* FALLTHROUGH */
			case HOST_NOT_FOUND:
				/* keep trying */
				break;
			case TRY_AGAIN:
				if (hp->rcode == SERVFAIL) {
					/* try next search element, if any */
					got_servfail++;
					break;
				}
				/* FALLTHROUGH */
			default:
				/* anything else implies that we're done */
				done++;
			}
			/*
			 * if we got here for some reason other than DNSRCH,
			 * we only wanted one iteration of the loop, so stop.
			 */
			if (!(_res.options & RES_DNSRCH))
			        done++;
		}
	}

	/*
	 * if we have not already tried the name "as is", do that now.
	 * note that we do this regardless of how many dots were in the
	 * name or whether it ends with a dot.
	 */
	if (!tried_as_is && (dots || !(_res.options & RES_NOTLDQUERY))) {
		ret = res_querydomainN(name, NULL, target);
		if (ret > 0)
			return (ret);
	}

	/*
	 * if we got here, we didn't satisfy the search.
	 * if we did an initial full query, return that query's h_errno
	 * (note that we wouldn't be here if that query had succeeded).
	 * else if we ever got a nodata, send that back as the reason.
	 * else send back meaningless h_errno, that being the one from
	 * the last DNSRCH we did.
	 */
	if (saved_herrno != -1)
		h_errno = saved_herrno;
	else if (got_nodata)
		h_errno = NO_DATA;
	else if (got_servfail)
		h_errno = TRY_AGAIN;
	return (-1);
}

/*
 * Perform a call on res_query on the concatenation of name and domain,
 * removing a trailing dot from name if domain is NULL.
 */
static int
res_querydomainN(name, domain, target)
	const char *name, *domain;
	struct res_target *target;
{
	char nbuf[MAXDNAME];
	const char *longname = nbuf;
	size_t n, d;

	if ((_res.options & RES_INIT) == 0 && res_init() == -1) {
		h_errno = NETDB_INTERNAL;
		return (-1);
	}
#ifdef DEBUG
	if (_res.options & RES_DEBUG)
		printf(";; res_querydomain(%s, %s)\n",
			name, domain?domain:"<Nil>");
#endif
	if (domain == NULL) {
		/*
		 * Check for trailing '.';
		 * copy without '.' if present.
		 */
		n = strlen(name);
		if (n >= MAXDNAME) {
			h_errno = NO_RECOVERY;
			return (-1);
		}
		if (n > 0 && name[--n] == '.') {
			strncpy(nbuf, name, n);
			nbuf[n] = '\0';
		} else
			longname = name;
	} else {
		n = strlen(name);
		d = strlen(domain);
		if (n + d + 1 >= MAXDNAME) {
			h_errno = NO_RECOVERY;
			return (-1);
		}
		snprintf(nbuf, sizeof(nbuf), "%s.%s", name, domain);
	}
	return (res_queryN(longname, target));
}

#endif	/* os dependent portion */
