/*	$KAME: dstsort.c,v 1.3 2001/08/20 02:32:40 itojun Exp $	*/

/*
 * Copyright (C) 2000 WIDE Project.
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
 * Sort AF_INET6 destination addresses based on
 * draft-ietf-ipngwg-default-addr-select-00.txt.
 * It affects AF_INET6 addresses only.
 *
 * XXX calls getifaddrs() only once, can't adapt to interface addr addition
 * XXX thread unsafe
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <ifaddrs.h>

struct policy {
	struct policy *next;

	struct sockaddr_in6 prefix;
	struct sockaddr_in6 mask;
	int precedence;
	int label;
	int matchsrclabel;
	int candidatesrc;
	int prefersrc;
};

static struct policy *policytab = NULL;
static struct ifaddrs *ifap;
static int initialized = 0;

static struct policy *getpolicy __P((char *, int, int, int, int,
	struct policy *));
static int init __P((void));
static int maskcmp __P((struct in6_addr *, struct in6_addr *,
	struct in6_addr *));
static struct policy *find __P((struct addrinfo *));
static int precedence __P((struct addrinfo *));
static int label __P((struct addrinfo *));
static int matchsrclabel __P((struct addrinfo *));
static int addrcmp __P((void *, void *));

#define SIN6(ai)	((struct sockaddr_in6 *)((ai)->ai_addr))
#define SIN6_ADDR(ai)	(&SIN6(ai)->sin6_addr)

static struct policy *
getpolicy(prefix, mask, precedence, label, matchsrclabel, tree)
	char *prefix;
	int mask;
	int precedence;
	int label;
	int matchsrclabel;
	struct policy *tree;
{
	struct policy *p = NULL;
	struct addrinfo hints, *res = NULL;
	int error;

	p = (struct policy *)malloc(sizeof(*p));
	if (!p)
		goto fail;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	error = getaddrinfo(prefix, NULL, &hints, &res);
	if (error)
		goto fail;
	if (res->ai_addrlen != sizeof(p->prefix))
		goto fail;
	memcpy(&p->prefix, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	memset(&p->mask, 0, sizeof(p->mask));
	memset(&p->mask.sin6_addr, 0xff, mask / 8);
	p->precedence = precedence;
	p->label = label;
	p->matchsrclabel = matchsrclabel;

	p->next = tree;
	return p;

fail:
	if (p)
		free(p);
	if (res)
		free(res);
	while (tree) {
		p = tree->next;
		free(tree);
		tree = p;
	}
	return NULL;
}

static int
init()
{
#define GETPOLICYTAB(p, x, y, z, u, v) \
do { \
	(p) = getpolicy((x), (y), (z), (u), (v), (p));	\
	if (!(p))						\
		goto fail;					\
} while (0)
	struct policy *p = NULL;
	struct policy *q = NULL;
	struct ifaddrs *ifa;
	int candidatesrc, prefersrc;
	struct in6_ifreq ifr;
	int s = -1;
	int matchid;

	if (policytab != NULL)
		goto fail;
	s = socket(AF_INET6, SOCK_STREAM, 0);
	if (s < 0)
		goto fail;
	p = NULL;

	/*
	 * Place long prefix earlier.  The order DOES matter.
	 * Label and MatchSrcLabel are just id, numerical order
	 * doesn't matter.
	 */
	GETPOLICYTAB(p, "::", 0, 20, 3, 3);
	GETPOLICYTAB(p, "::", 96, 10, 1, 1);
	GETPOLICYTAB(p, "2002::", 16, 10, 2, 2);
	/* add policy table in per-interface manner */
	matchid = 4;
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		struct in6_addr *in6;
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		in6 = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
		if (IN6_IS_ADDR_LINKLOCAL(in6)) {
			GETPOLICYTAB(p, "fe80::", 10, 40, matchid, matchid);
			p->prefix.sin6_scope_id =
			    *(u_int16_t *)(&in6->s6_addr[2]);
		} else if (IN6_IS_ADDR_SITELOCAL(in6)) {
			GETPOLICYTAB(p, "fec0::", 10, 30, matchid, matchid);
			p->prefix.sin6_scope_id =
			    *(u_int16_t *)(&in6->s6_addr[2]);
		}

		matchid++;
	}
	policytab = p;

	/* O(n^2) */
	for (p = policytab; p; p = p->next) {
		candidatesrc = prefersrc = 0;
		for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr->sa_family != AF_INET6)
				continue;
			if (maskcmp(&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr,
					&p->prefix.sin6_addr,
					&p->mask.sin6_addr) != 1)
				continue;

			candidatesrc++;

			if (sizeof(ifr.ifr_addr) < ifa->ifa_addr->sa_len)
				continue;
			memset(&ifr, 0, sizeof(ifr));
			memcpy(ifr.ifr_name, ifa->ifa_name,
			    sizeof(ifr.ifr_name));
			memcpy(&ifr.ifr_addr, ifa->ifa_addr,
			    ifa->ifa_addr->sa_len);
			if (ioctl(s, SIOCGIFAFLAG_IN6, (caddr_t)&ifr) < 0)
				goto fail;
			if (ifr.ifr_ifru.ifru_flags6 & IN6_IFF_NOTREADY)
				continue;
			prefersrc++;
		}
		p->candidatesrc = candidatesrc;
		p->prefersrc = prefersrc;
	}

	close(s);
	return 0;

fail:
	if (s >= 0)
		close(s);
	while (p) {
		q = p->next;
		free(p);
		p = q;
	}

	return -1;
#undef GETPOLICYTAB
}

static int
maskcmp(a, b, m)
	struct in6_addr *a;
	struct in6_addr *b;
	struct in6_addr *m;
{
	size_t i;

	for (i = 0; i < sizeof(struct in6_addr); i++) {
		if ((a->s6_addr[i] & m->s6_addr[i]) !=
				(b->s6_addr[i] & m->s6_addr[i]))
			return 0;
	}

	return 1;
}

static struct policy *
find(ai)
	struct addrinfo *ai;
{
	struct policy *p = NULL;

	if (ai->ai_family != AF_INET6)
		return NULL;

	for (p = policytab; p; p = p->next) {
		if (maskcmp(SIN6_ADDR(ai), &p->prefix.sin6_addr,
				&p->mask.sin6_addr) == 1 &&
		    p->prefix.sin6_scope_id == SIN6(ai)->sin6_scope_id) {
			return p;
		}
	}

	return NULL;
}

static int
precedence(ai)
	struct addrinfo *ai;
{
	struct policy *p;

	p = find(ai);
	return p ? p->precedence : -1;
}

static int
label(ai)
	struct addrinfo *ai;
{
	struct policy *p;

	p = find(ai);
	return p ? p->label : -1;
}

static int
matchsrclabel(ai)
	struct addrinfo *ai;
{
	struct policy *p;

	p = find(ai);
	return p ? p->matchsrclabel : -1;
}

static int
matchsrc(ai)
	struct addrinfo *ai;
{
	struct policy *p;

	p = find(ai);
	return p ? p->candidatesrc : 0;
}

/*------------------------------------------------------------*/

/* draft-ietf-ipngwg-default-addr-select-00 section 3 */
static int
addrcmp(arg1, arg2)
	void *arg1;
	void *arg2;
{
	struct addrinfo *p = *(struct addrinfo **)arg1;
	struct addrinfo *q = *(struct addrinfo **)arg2;
	struct sockaddr_in6 *a;
	struct sockaddr_in6 *b;
	int pv, qv;
	char hbuf[NI_MAXHOST];

	if (p->ai_family != q->ai_family || p->ai_addrlen != q->ai_addrlen)
		return 0;

	if (p->ai_family != AF_INET6)
		return 0;

	/* rule 1 */
	pv = matchsrc(p); qv = matchsrc(q);
	if (pv > 0 && qv <= 0)
		return -1;
	else if (pv <= 0 && qv > 0)
		return 1;

	/* rule 2 */
	pv = precedence(p); qv = precedence(q);
	if (pv != qv) {
		/* larger is better */
		return qv - pv;
	}

	/* rule 3 - not yet, too complex */

	/* rule 4 */
	return -1;
}

struct addrinfo *
sortdstaddr(ai)
	struct addrinfo *ai;
{
	struct addrinfo **idx;
	struct addrinfo *p;
	size_t nelem;
	size_t i;

	if (!initialized) {
		if (getifaddrs(&ifap) < 0)
			return NULL;
		if (init() < 0) {
			freeifaddrs(ifap);
			ifap = NULL;
			return NULL;
		}
		initialized++;
	}

	/* no need to sort */
	if (!ai && !ai->ai_next)
		return ai;

	nelem = 0;
	for (p = ai; p; p = p->ai_next)
		nelem++;
	idx = (struct addrinfo **)malloc(nelem * sizeof(struct addrinfo *));
	if (idx == NULL)
		return ai;

	i = 0;
	for (p = ai; p; p = p->ai_next)
		idx[i++] = p;

	qsort(idx, nelem, sizeof(idx[0]), addrcmp);

	for (i = 0; i < nelem - 1; i++)
		idx[i]->ai_next = idx[i + 1];
	idx[nelem - 1]->ai_next = NULL;

	p = idx[0];
	free(idx);
	return p;
}
