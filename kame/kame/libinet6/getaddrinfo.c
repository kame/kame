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
 * "#ifdef FAITH" part is local hack for supporting IPv4-v6 translator.
 *
 * Issues to be discussed:
 * - Thread safe-ness must be checked.
 * - Return values.  There are nonstandard return values defined and used
 *   in the source code.  This is because RFC2553 is silent about which error
 *   code must be returned for which situation.
 * - PF_UNSPEC case would be handled in getipnodebyname() with the AI_ALL flag.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif 

#include <sys/types.h>
#include <sys/param.h>
#if 0
#include <sys/sysctl.h>
#endif
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
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

#ifndef HAVE_PORTABLE_PROTOTYPE
#include "cdecl_ext.h"
#endif 

#ifndef HAVE_U_INT32_T
#include "bittypes.h"
#endif 

#ifndef HAVE_SOCKADDR_STORAGE
#include "sockstorage.h"
#endif 

#ifndef HAVE_ADDRINFO
#include "addrinfo.h"
#endif

#if defined(__KAME__) && defined(INET6)
# define FAITH
#endif

#define SUCCESS 0
#define ANY 0
#define YES 1
#define NO  0

#ifdef FAITH
static int translate = NO;
static struct in6_addr faith_prefix = IN6ADDR_ANY_INIT;
#endif

static const char in_addrany[] = { 0, 0, 0, 0 };
static const char in6_addrany[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
static const char in_loopback[] = { 127, 0, 0, 1 }; 
static const char in6_loopback[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
};

struct sockinet {
	u_char	si_len;
	u_char	si_family;
	u_short	si_port;
	u_int32_t si_scope_id;
};

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
};

static const struct explore explore[] = {
#if 0
	{ PF_LOCAL, ANY, ANY, NULL },
#endif
#ifdef INET6
	{ PF_INET6, SOCK_DGRAM, IPPROTO_UDP, "udp" },
	{ PF_INET6, SOCK_STREAM, IPPROTO_TCP, "tcp" },
	{ PF_INET6, SOCK_RAW, ANY },
#endif
	{ PF_INET, SOCK_DGRAM, IPPROTO_UDP, "udp" },
	{ PF_INET, SOCK_STREAM, IPPROTO_TCP, "tcp" },
	{ PF_INET, SOCK_RAW, ANY, NULL },
	{ -1, 0, 0, NULL },
};

#ifdef USE_GETIPNODEBY
static const struct explore explore_getipnodeby[] = {
#if 0
	{ PF_LOCAL, ANY, ANY, NULL },
#endif
	{ PF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, "udp" },
	{ PF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, "tcp" },
	{ PF_UNSPEC, SOCK_RAW, ANY },
	{ -1, 0, 0, NULL },
};
#endif

#ifdef INET6
#define PTON_MAX	16
#else
#define PTON_MAX	4
#endif


static int str_isnumber __P((const char *));
static int explore_null __P((const struct addrinfo *, const char *,
	const char *, struct addrinfo **));
static int explore_numeric __P((const struct addrinfo *, const char *,
	const char *, struct addrinfo **));
static int explore_numeric_scope __P((const struct addrinfo *, const char *,
	const char *, struct addrinfo **));
static int get_name __P((const char *, const struct afd *, struct addrinfo **,
	char *, const struct addrinfo *, const char *));
static int get_addr __P((const char *, const char *, int, struct addrinfo **,
			struct addrinfo *));
static int get_addr0 __P((const char *, const char *, int, struct addrinfo **,
			struct addrinfo *));
static int get_canonname __P((const struct addrinfo *,
	struct addrinfo *, const char *));
static struct addrinfo *get_ai __P((const struct addrinfo *,
	const struct afd *, const char *));
static int get_portmatch __P((const struct addrinfo *, const char *));
static int get_port __P((struct addrinfo *, const char *, int));
static const struct afd *find_afd __P((int));
#ifndef USE_GETIPNODEBY
static struct addrinfo *res_append __P((struct addrinfo *, struct addrinfo *));
#endif

static char *ai_errlist[] = {
	"Success",
	"Address family for hostname not supported",	/* EAI_ADDRFAMILY */
	"Temporary failure in name resolution",		/* EAI_AGAIN      */
	"Invalid value for ai_flags",		       	/* EAI_BADFLAGS   */
	"Non-recoverable failure in name resolution", 	/* EAI_FAIL       */
	"ai_family not supported",			/* EAI_FAMILY     */
	"Memory allocation failure", 			/* EAI_MEMORY     */
	"No address associated with hostname", 		/* EAI_NODATA     */
	"hostname nor servname provided, or not known",	/* EAI_NONAME     */
	"servname not supported for ai_socktype",	/* EAI_SERVICE    */
	"ai_socktype not supported", 			/* EAI_SOCKTYPE   */
	"System error returned in errno", 		/* EAI_SYSTEM     */
	"Invalid value for hints",			/* EAI_BADHINTS	  */
	"Resolved protocol is unknown",			/* EAI_PROTOCOL   */
	"Unknown error", 				/* EAI_MAX        */
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
} while (0)

#define GET_PORT(ai, serv) \
do { \
	/* external reference: error and label free */ \
	error = get_port((ai), (serv), 0); \
	if (error != 0) \
		goto free; \
} while (0)

#define GET_CANONNAME(ai, str) \
do { \
	/* external reference: pai, error and label free */ \
	error = get_canonname(pai, (ai), (str)); \
	if (error != 0) \
		goto free; \
} while (0)

#define ERR(err) \
do { \
	/* external reference: error, and label bad */ \
	error = (err); \
	goto bad; \
} while (0)

#define MATCH_FAMILY(x, y)	((x) == PF_UNSPEC || (x) == (y))
#define MATCH(x, y)		((x) == ANY || (x) == (y))

char *
gai_strerror(ecode)
	int ecode;
{
	if (ecode < 0 || ecode > EAI_MAX)
		ecode = EAI_MAX;
	return ai_errlist[ecode];
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
	} while ((ai = next) != NULL);
}

static int
str_isnumber(p)
	const char *p;
{
	char *q = (char *)p;
	while (*q) {
		if (! isdigit(*q))
			return NO;
		q++;
	}
	return YES;
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
	struct addrinfo ai;
	struct addrinfo ai0;
	struct addrinfo *pai;
	const struct explore *ex;

#ifdef FAITH
	static int firsttime = 1;

	if (firsttime) {
		/* translator hack */
		char *q = getenv("GAI");
		if (q && inet_pton(AF_INET6, q, &faith_prefix) == 1)
			translate = YES;
		firsttime = 0;
	}
#endif

	sentinel.ai_next = NULL;
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
				if (pai->ai_family != ex->e_af)
					continue;
				if (ex->e_socktype == ANY)
					continue;
				if (ex->e_protocol == ANY)
					continue;
				if (pai->ai_socktype == ex->e_socktype
				 && pai->ai_protocol != ex->e_protocol) {
					ERR(EAI_BADHINTS);
				}
			}
		}
	}

	/*
	 * check for special cases.  (1) numeric servname is disallowed if
	 * socktype/protocol are left unspecified. (2) servname is disallowed
	 * for raw and other inet{,6} sockets.
	 */
	if (MATCH_FAMILY(pai->ai_family, PF_INET)
	 || MATCH_FAMILY(pai->ai_family, PF_INET6)) {
		ai0 = *pai;

		if (pai->ai_family == PF_UNSPEC)
			pai->ai_family = PF_INET6;
		error = get_portmatch(pai, servname);
		if (error)
			ERR(error);

		*pai = ai0;
	}

	ai0 = *pai;

	/* NULL hostname, or numeric hostname */
	for (ex = explore; ex->e_af >= 0; ex++) {
		*pai = ai0;

		if (!MATCH_FAMILY(pai->ai_family, ex->e_af))
			continue;
		if (!MATCH(pai->ai_socktype, ex->e_socktype))
			continue;
		if (!MATCH(pai->ai_protocol, ex->e_protocol))
			continue;

		if (pai->ai_family == PF_UNSPEC)
			pai->ai_family = ex->e_af;
		if (pai->ai_socktype == ANY)
			pai->ai_socktype = ex->e_socktype;
		if (pai->ai_protocol == ANY)
			pai->ai_protocol = ex->e_protocol;

		if (hostname == NULL)
			error = explore_null(pai, hostname, servname, &cur->ai_next);
		else
			error = explore_numeric_scope(pai, hostname, servname, &cur->ai_next);

		if (error)
			goto free;

		while (cur && cur->ai_next)
			cur = cur->ai_next;
	}

	/*
	 * XXX
	 * If numreic representation of AF1 can be interpreted as FQDN
	 * representation of AF2, we need to think again about the code below.
	 */
	if (sentinel.ai_next)
		goto good;

	if (pai->ai_flags & AI_NUMERICHOST)
		ERR(EAI_NONAME);
	if (hostname == NULL)
		ERR(EAI_NONAME);

	/* hostname as alphabetical name */
#ifdef USE_GETIPNODEBY
	for (ex = explore_getipnodeby; ex->e_af >= 0; ex++)
#else
	for (ex = explore; ex->e_af >= 0; ex++)
#endif
	{
		*pai = ai0;

		if (!MATCH_FAMILY(pai->ai_family, ex->e_af))
			continue;
		if (!MATCH(pai->ai_socktype, ex->e_socktype))
			continue;
		if (!MATCH(pai->ai_protocol, ex->e_protocol))
			continue;

		if (pai->ai_family == PF_UNSPEC)
			pai->ai_family = ex->e_af;
		if (pai->ai_socktype == ANY)
			pai->ai_socktype = ex->e_socktype;
		if (pai->ai_protocol == ANY)
			pai->ai_protocol = ex->e_protocol;

		error = get_addr(hostname, servname, pai->ai_family, &cur->ai_next, pai);

		if (error)
			goto free;

		while (cur && cur->ai_next)
			cur = cur->ai_next;
	}

	if (error)
		goto free;
	if (error == 0) {
		if (sentinel.ai_next) {
 good:
			*res = sentinel.ai_next;
			return SUCCESS;
		} else
			error = EAI_FAIL;
	}
 free:
 bad:
	if (sentinel.ai_next)
		freeaddrinfo(sentinel.ai_next);
	*res = NULL;
	return error;
}

/*
 * hostname == NULL.
 * passive socket -> anyaddr (0.0.0.0 or ::)
 * non-passive socket -> localhost (127.0.0.1 or ::1)
 */
static int
explore_null(pai, hostname, servname, res)
	const struct addrinfo *pai;
	const char *hostname;
	const char *servname;
	struct addrinfo **res;
{
	int s;
	const struct afd *afd;
	struct addrinfo *cur;
	struct addrinfo sentinel;
	int error;

	*res = NULL;
	sentinel.ai_next = NULL;
	cur = &sentinel;

	/*
	 * filter out AFs that are not supported by the kernel
	 * XXX errno?
	 */
	s = socket(pai->ai_family, SOCK_DGRAM, 0);
	if (s < 0)
		return 0;
	close(s);

	/*
	 * if the servname does not match socktype/protocol, ignore it.
	 */
	if (get_portmatch(pai, servname) != 0)
		return 0;

	afd = find_afd(pai->ai_family);

	if (pai->ai_flags & AI_PASSIVE) {
		GET_AI(*res, afd, afd->a_addrany);
		/* xxx meaningless?
		 * GET_CANONNAME(cur->ai_next, "anyaddr");
		 */
		GET_PORT(cur->ai_next, servname);
	} else {
		GET_AI(cur->ai_next, afd, afd->a_loopback);
		/* xxx meaningless?
		 * GET_CANONNAME(cur->ai_next, "localhost");
		 */
		GET_PORT(cur->ai_next, servname);
	}
	cur = cur->ai_next;

	*res = sentinel.ai_next;
	return 0;

free:
	freeaddrinfo(sentinel.ai_next);
	return error;
}

/*
 * numeric hostname
 */
static int
explore_numeric(pai, hostname, servname, res)
	const struct addrinfo *pai;
	const char *hostname;
	const char *servname;
	struct addrinfo **res;
{
	const struct afd *afd;
	struct addrinfo *cur;
	struct addrinfo sentinel;
	int error;
	char pton[PTON_MAX];
	int flags;

	*res = NULL;
	sentinel.ai_next = NULL;
	cur = &sentinel;

	/*
	 * if the servname does not match socktype/protocol, ignore it.
	 */
	if (get_portmatch(pai, servname) != 0)
		return 0;

	afd = find_afd(pai->ai_family);
	flags = pai->ai_flags;

	if (inet_pton(afd->a_af, hostname, pton) == 1) {
		u_int32_t v4a;
#ifdef INET6
		u_char pfx;
#endif

		switch (afd->a_af) {
		case AF_INET:
			v4a = (u_int32_t)ntohl(((struct in_addr *)pton)->s_addr);
			if (IN_MULTICAST(v4a) || IN_EXPERIMENTAL(v4a))
				flags &= ~AI_CANONNAME;
			v4a >>= IN_CLASSA_NSHIFT;
			if (v4a == 0 || v4a == IN_LOOPBACKNET)
				flags &= ~AI_CANONNAME;
			break;
#ifdef INET6
		case AF_INET6:
			pfx = ((struct in6_addr *)pton)->s6_addr[0];
			if (pfx == 0 || pfx == 0xfe || pfx == 0xff)
				flags &= ~AI_CANONNAME;
			break;
#endif
		}

		if (pai->ai_family == afd->a_af ||
		    pai->ai_family == PF_UNSPEC /*?*/) {
			if (! (flags & AI_CANONNAME)) {
				GET_AI(cur->ai_next, afd, pton);
				GET_PORT(cur->ai_next, servname);
			} else {
				/*
				 * if AI_CANONNAME and if reverse lookup
				 * fail, return ai anyway to pacify
				 * calling application.
				 *
				 * XXX getaddrinfo() is a name->address
				 * translation function, and it looks
				 * strange that we do addr->name
				 * translation here.
				 */
				get_name(pton, afd, &cur->ai_next,
					pton, pai, servname);
			}
			cur = cur->ai_next;
		} else 
			ERR(EAI_FAMILY);	/*xxx*/
	}

	*res = sentinel.ai_next;
	return 0;

free:
bad:
	freeaddrinfo(sentinel.ai_next);
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
#ifndef SCOPE_DELIMITER
	return explore_numeric(pai, hostname, servname, res);
#else
	const struct afd *afd;
	struct addrinfo *cur;
	int error;
	char *cp, *hostname2 = NULL;
	int scope;
	struct sockaddr_in6 *sin6;

	/*
	 * if the servname does not match socktype/protocol, ignore it.
	 */
	if (get_portmatch(pai, servname) != 0)
		return 0;

	afd = find_afd(pai->ai_family);
	if (!afd->a_scoped)
		return explore_numeric(pai, hostname, servname, res);

	cp = strchr(hostname, SCOPE_DELIMITER);
	if (cp == NULL)
		return explore_numeric(pai, hostname, servname, res);

	/*
	 * Handle special case of <scoped_address><delimiter><scope id>
	 */
	hostname2 = strdup(hostname);
	if (hostname2 == NULL)
		return EAI_MEMORY;
	/* terminate at the delimiter */
	hostname2[cp - hostname] = '\0';

	cp++;
	switch (pai->ai_family) {
#ifdef INET6
	case AF_INET6:
		scope = if_nametoindex(cp);
		break;
#endif
	}

	error = explore_numeric(pai, hostname2, servname, res);
	if (error == 0) {
		for (cur = *res; cur; cur = cur->ai_next) {
			if (cur->ai_family != AF_INET6)
				continue;
			sin6 = (struct sockaddr_in6 *)cur->ai_addr;
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) ||
			    IN6_IS_ADDR_MC_LINKLOCAL(&sin6->sin6_addr))
				sin6->sin6_scope_id = scope;
		}
	}

	free(hostname2);

	return error;
#endif
}

static int
get_name(addr, afd, res, numaddr, pai, servname)
	const char *addr;
	const struct afd *afd;
	struct addrinfo **res;
	char *numaddr;
	const struct addrinfo *pai;
	const char *servname;
{
	struct hostent *hp;
	struct addrinfo *cur;
	int error = 0;
#ifdef USE_GETIPNODEBY
	int h_error;

	hp = getipnodebyaddr(addr, afd->a_addrlen, afd->a_af, &h_error);
#else
	hp = gethostbyaddr(addr, afd->a_addrlen, afd->a_af);
#endif
	if (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		GET_AI(cur, afd, hp->h_addr_list[0]);
		GET_PORT(cur, servname);
		GET_CANONNAME(cur, hp->h_name);
	} else {
		GET_AI(cur, afd, numaddr);
		GET_PORT(cur, servname);
	}
	
#ifdef USE_GETIPNODEBY
	if (hp)
		freehostent(hp);
#endif
	*res = cur;
	return SUCCESS;
 free:
	if (cur)
		freeaddrinfo(cur);
#ifdef USE_GETIPNODEBY
	if (hp)
		freehostent(hp);
#endif
 /* bad: */
	*res = NULL;
	return error;
}

static int
get_addr(hostname, servname, af, res0, pai)
	const char *hostname;
	const char *servname;
	int af;
	struct addrinfo **res0;
	struct addrinfo *pai;
{
#ifdef USE_GETIPNODEBY
	struct addrinfo pai0;

	/*
	 * if the servname does not match socktype/protocol, ignore it.
	 * if PF_UNSPEC is passed down to us, treat it as PF_INET6.
	 */
	pai0 = *pai;
	if (pai0.ai_family == PF_UNSPEC)
		pai0.ai_family = PF_INET6;
	if (get_portmatch(&pai0, servname) != 0)
		return 0;

	return get_addr0(hostname, servname, af, res0, pai);
#else
	int i, error, ekeep;
	struct addrinfo *res;
	int retry;
	int s;

	/*
	 * if the servname does not match socktype/protocol, ignore it.
	 */
	if (get_portmatch(pai, servname) != 0)
		return 0;

	*res0 = NULL;
	ekeep = 0;
	error = 0;
	for (i = 0; afdl[i].a_af; i++) {
		retry = 0;
		if (af == AF_UNSPEC) {
			/*
			 * filter out AFs that are not supported by the kernel
			 * XXX errno?
			 */
			s = socket(afdl[i].a_af, SOCK_DGRAM, 0);
			if (s < 0)
				continue;
			close(s);
		} else {
			if (af != afdl[i].a_af)
				continue;
		}
		/* It is WRONG, we need getipnodebyname(). */
again:
		error = get_addr0(hostname, servname, afdl[i].a_af, &res, pai);
		switch (error) {
		case EAI_AGAIN:
			if (++retry < 3)
				goto again;
			/* FALL THROUGH*/
		default:
			if (ekeep == 0)
				ekeep = error;
			break;
		}
		if (res) {
			*res0 = res_append(*res0, res);
			res = NULL;
		}
	}

	/* if we got something, it's okay */
	if (*res0)
		return 0;

	return error ? error : ekeep;
#endif
}

static int
get_addr0(hostname, servname, af, res, pai)
	const char *hostname;
	const char *servname;
	int af;
	struct addrinfo **res;
	struct addrinfo *pai;
{
	struct addrinfo sentinel;
	struct hostent *hp;
	struct addrinfo *top, *cur;
	const struct afd *afd;
	const struct afd *afd6;
	int i, error = 0, h_error;
	char *ap;
#ifndef USE_GETIPNODEBY
	extern int h_errno;
#endif

	top = NULL;
	sentinel.ai_next = NULL;
	cur = &sentinel;
#ifdef USE_GETIPNODEBY
#ifdef INET6
	if (af == AF_UNSPEC) {
		hp = getipnodebyname(hostname, AF_INET6,
				AI_ADDRCONFIG|AI_ALL|AI_V4MAPPED, &h_error);
	} else
#endif
		hp = getipnodebyname(hostname, af, AI_ADDRCONFIG, &h_error);
#else
	if (af == AF_UNSPEC) {
		error = EAI_FAIL;
		goto bad;
	}
	hp = gethostbyname2(hostname, af);
	h_error = h_errno;
#endif
	if (hp == NULL) {
		switch (h_error) {
		case HOST_NOT_FOUND:
		case NO_DATA:
			error = EAI_NODATA;
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
		goto bad;
	}

	if ((hp->h_name == NULL) || (hp->h_name[0] == 0) ||
	    (hp->h_addr_list[0] == NULL))
		ERR(EAI_FAIL);
	
	for (i = 0; (ap = hp->h_addr_list[i]) != NULL; i++) {
		afd6 = find_afd(PF_INET6);
		if (af == PF_UNSPEC) {
#ifndef INET6
			afd = find_afd(PF_INET);
#else
			if (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)ap)) {
				ap += sizeof(struct in6_addr) -
					sizeof(struct in_addr);
				afd = find_afd(PF_INET);
			} else
				afd = afd6;
#endif
		} else if (af == PF_INET6)
			afd = afd6;
		else
			afd = find_afd(af);
#ifdef FAITH
		if (translate && afd->a_af == AF_INET) {
			struct in6_addr *in6;

			GET_AI(cur->ai_next, afd6, ap);
			GET_PORT(cur->ai_next, servname);
			in6 = &((struct sockaddr_in6 *)cur->ai_next->ai_addr)->sin6_addr;
			memcpy(&in6->s6_addr[0], &faith_prefix,
			    sizeof(struct in6_addr) - sizeof(struct in_addr));
			memcpy(&in6->s6_addr[12], ap, sizeof(struct in_addr));
		} else
#endif /* FAITH */
		{
			GET_AI(cur->ai_next, afd, ap);
			GET_PORT(cur->ai_next, servname);
		}
		if (cur == &sentinel) {
			top = cur->ai_next;
			GET_CANONNAME(top, hp->h_name);
		}
		cur = cur->ai_next;
	}
#ifdef USE_GETIPNODEBY
	freehostent(hp);
#endif
	*res = top;
	return SUCCESS;
 free:
	if (top)
		freeaddrinfo(top);
#ifdef USE_GETIPNODEBY
	if (hp)
		freehostent(hp);
#endif
 bad:
	*res = NULL;
	return error;
}

static int
get_canonname(pai, ai, str)
	const struct addrinfo *pai;
	struct addrinfo *ai;
	const char *str;
{
	if ((pai->ai_flags & AI_CANONNAME) != 0) {
		ai->ai_canonname = (char *)malloc(strlen(str) + 1);
		if (ai->ai_canonname == NULL)
			return EAI_MEMORY;
		strcpy(ai->ai_canonname, str);
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
	ai->ai_addr = (struct sockaddr *)(ai + 1);
	memset(ai->ai_addr, 0, afd->a_socklen);
#ifdef HAVE_SOCKADDR_SA_LEN
	ai->ai_addr->sa_len = afd->a_socklen;
#endif
	ai->ai_addrlen = afd->a_socklen;
	ai->ai_addr->sa_family = ai->ai_family = afd->a_af;
	p = (char *)(ai->ai_addr);
	memcpy(p + afd->a_off, addr, afd->a_addrlen);
	return ai;
}

static int
get_portmatch(ai, servname)
	const struct addrinfo *ai;
	const char *servname;
{
	/* get_port does not touch first argument. when matchonly == 1. */
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
	if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
		return 0;

	switch (ai->ai_socktype) {
	case SOCK_RAW:
		return EAI_SERVICE;
	case SOCK_DGRAM:
	case SOCK_STREAM:
		allownumeric = 1;
		break;
	case ANY:
		allownumeric = 0;
		break;
	default:
		return EAI_SOCKTYPE;
	}

	if (str_isnumber(servname)) {
		if (!allownumeric)
			return EAI_SOCKTYPE;
		port = htons(atoi(servname));
		if (port < 0 || port > 65535)
			return EAI_SERVICE;
	} else {
		switch (ai->ai_socktype) {
		case SOCK_DGRAM:
			proto = "udp";
			break;
		case SOCK_STREAM:
			proto = "tcp";
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
			((struct sockaddr_in *)ai->ai_addr)->sin_port = port;
			break;
#ifdef INET6
		case AF_INET6:
			((struct sockaddr_in6 *)ai->ai_addr)->sin6_port = port;
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

#ifndef USE_GETIPNODEBY
static struct addrinfo *
res_append(a, b)
	struct addrinfo *a;
	struct addrinfo *b;
{
	struct addrinfo *p;

	if (a == NULL)
		return b;
	for (p = a; p && p->ai_next; p = p->ai_next)
		;
	p->ai_next = b;
	return a;
}
#endif
