/*	$KAME: cfparse.y,v 1.21 2003/03/14 11:06:26 jinmei Exp $	*/

/*
 * Copyright (C) 2002 WIDE Project.
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
%{
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <string.h>

#include "dhcp6.h"
#include "config.h"
#include "common.h"

extern int lineno;
extern int cfdebug;

extern void yywarn __P((char *, ...))
	__attribute__((__format__(__printf__, 1, 2)));
extern void yyerror __P((char *, ...))
	__attribute__((__format__(__printf__, 1, 2)));

#define MAKE_NAMELIST(l, n, p) do { \
	(l) = (struct cf_namelist *)malloc(sizeof(*(l))); \
	if ((l) == NULL) { \
		yywarn("can't allocate memory"); \
		if (p) cleanup_cflist(p); \
		return (-1); \
	} \
	memset((l), 0, sizeof(*(l))); \
	l->line = lineno; \
	l->name = (n); \
	l->params = (p); \
	} while (0)

#define MAKE_CFLIST(l, t, pp, pl) do { \
	(l) = (struct cf_list *)malloc(sizeof(*(l))); \
	if ((l) == NULL) { \
		yywarn("can't allocate memory"); \
		if (pp) free(pp); \
		if (pl) cleanup_cflist(pl); \
		return (-1); \
	} \
	memset((l), 0, sizeof(*(l))); \
	l->line = lineno; \
	l->type = (t); \
	l->ptr = (pp); \
	l->list = (pl); \
	} while (0)

static struct cf_namelist *iflist_head, *hostlist_head, *iapdlist_head;
struct cf_list *cf_dns_list;

extern int yylex __P((void));
static void cleanup __P((void));
static void cleanup_namelist __P((struct cf_namelist *));
static void cleanup_cflist __P((struct cf_list *));
%}

%token INTERFACE IFNAME
%token PREFIX_INTERFACE SLA_ID SLA_LEN DUID_ID
%token ID_ASSOC IA_PD IAID
%token REQUEST SEND ALLOW PREFERENCE
%token HOST HOSTNAME DUID
%token OPTION RAPID_COMMIT IA_PD DNS_SERVERS
%token INFO_ONLY
%token NUMBER SLASH EOS BCL ECL STRING PREFIX INFINITY
%token COMMA

%union {
	long long num;
	char* str;
	struct cf_list *list;
	struct dhcp6_prefix *prefix;
}

%type <str> IFNAME HOSTNAME DUID_ID STRING IAID
%type <num> NUMBER duration
%type <list> declaration declarations dhcpoption ifparam ifparams
%type <list> address_list address_list_ent
%type <list> iaconf_list iaconf prefix_interface
%type <prefix> prefixparam

%%
statements:
		/* empty */
	|	statements statement
	;

statement:
		interface_statement
	|	host_statement
	|	option_statement
	|	ia_statement
	;

interface_statement:
	INTERFACE IFNAME BCL declarations ECL EOS 
	{
		struct cf_namelist *ifl;

		MAKE_NAMELIST(ifl, $2, $4);

		if (add_namelist(ifl, &iflist_head))
			return (-1);
	}
	;

host_statement:
	HOST HOSTNAME BCL declarations ECL EOS
	{
		struct cf_namelist *host;

		MAKE_NAMELIST(host, $2, $4);

		if (add_namelist(host, &hostlist_head))
			return (-1);
	}
	;

option_statement:
	OPTION DNS_SERVERS address_list EOS
	{
		if (cf_dns_list == NULL)
			cf_dns_list = $3;
		else {
			cf_dns_list->tail->next = $3;
			cf_dns_list->tail = $3->next;
		}
	}
	;

ia_statement:
		ID_ASSOC IA_PD IAID BCL iaconf_list ECL EOS
		{
			struct cf_namelist *iapd;

			MAKE_NAMELIST(iapd, $3, $5);

			if (add_namelist(iapd, &iapdlist_head))
				return (-1);
		}
	|	ID_ASSOC IA_PD BCL iaconf_list ECL EOS
		{
			struct cf_namelist *iapd;
			char *zero;

			if ((zero = strdup("0")) == NULL) {
				yywarn("can't allocate memory");
				return (-1);
			}
			MAKE_NAMELIST(iapd, zero, $4);

			if (add_namelist(iapd, &iapdlist_head))
				return (-1);
		}
	;

address_list:
		{ $$ = NULL; }
	|	address_list address_list_ent
		{
			struct cf_list *head;

			if ((head = $1) == NULL) {
				$2->next = NULL;
				$2->tail = $2;
				head = $2;
			} else {
				head->tail->next = $2;
				head->tail = $2;
			}

			$$ = head;
		}
	;

address_list_ent:
	STRING
	{
		struct cf_list *l;
		struct in6_addr a0, *a;

		if (inet_pton(AF_INET6, $1, &a0) != 1) {
			yywarn("invalid IPv6 address: %s", $1);
			free($1);
			return (-1);
		}
		if ((a = malloc(sizeof(*a))) == NULL) {
			yywarn("can't allocate memory");
			return (-1);
		}
		*a = a0;

		MAKE_CFLIST(l, ADDRESS_LIST_ENT, a, NULL);

		$$ = l;
	}

declarations:
		{ $$ = NULL; }
	|	declarations declaration
		{
			struct cf_list *head;

			if ((head = $1) == NULL) {
				$2->next = NULL;
				$2->tail = $2;
				head = $2;
			} else {
				head->tail->next = $2;
				head->tail = $2;
			}

			$$ = head;
		}
	;
	
declaration:
		SEND dhcpoption EOS
		{
			struct cf_list *l;

			MAKE_CFLIST(l, DECL_SEND, NULL, $2);

			$$ = l;
		}
	|	REQUEST dhcpoption EOS
		{
			struct cf_list *l;

			MAKE_CFLIST(l, DECL_REQUEST, NULL, $2);

			$$ = l;
		}
	|	INFO_ONLY EOS
		{
			struct cf_list *l;

			MAKE_CFLIST(l, DECL_INFO_ONLY, NULL, NULL);
			/* no value */
			$$ = l;
		}
	|	ALLOW dhcpoption EOS
		{
			struct cf_list *l;

			MAKE_CFLIST(l, DECL_ALLOW, NULL, $2);

			$$ = l;
		}
	|	DUID DUID_ID EOS
		{
			struct cf_list *l;

			MAKE_CFLIST(l, DECL_DUID, $2, NULL);

			$$ = l;
		}
	|	PREFIX prefixparam EOS
		{
			struct cf_list *l;

			MAKE_CFLIST(l, DECL_PREFIX, $2, NULL);

			$$ = l;
		}
	|	PREFERENCE NUMBER EOS
		{
			struct cf_list *l;

			MAKE_CFLIST(l, DECL_PREFERENCE, NULL, NULL);
			l->num = $2;

			$$ = l;
		}
	;

dhcpoption:
		RAPID_COMMIT
		{
			struct cf_list *l;

			MAKE_CFLIST(l, DHCPOPT_RAPID_COMMIT, NULL, NULL);
			/* no value */
			$$ = l;
		}
	|	IA_PD NUMBER
		{
			struct cf_list *l;

			MAKE_CFLIST(l, DHCPOPT_IA_PD, NULL, NULL);
			l->num = $2;
			$$ = l;
		}
	|	DNS_SERVERS	
		{
			struct cf_list *l;

			MAKE_CFLIST(l, DHCPOPT_DNS, NULL, NULL);
			/* currently no value */
			$$ = l;
		}
	;

prefixparam:
		STRING SLASH NUMBER duration
		{
			struct dhcp6_prefix pconf0, *pconf;		

			memset(&pconf0, 0, sizeof(pconf0));
			if (inet_pton(AF_INET6, $1, &pconf0.addr) != 1) {
				yywarn("invalid IPv6 address: %s", $1);
				free($1);
				return (-1);
			}
			free($1);
			/* validate other parameters later */
			pconf0.plen = $3;
			if ($4 < 0)
				pconf0.pltime = DHCP6_DURATITION_INFINITE;
			else
				pconf0.pltime = (u_int32_t)$4;
			pconf0.vltime = pconf0.pltime;

			if ((pconf = malloc(sizeof(*pconf))) == NULL) {
				yywarn("can't allocate memory");
				return (-1);
			}
			*pconf = pconf0;

			$$ = pconf;
		}
	|	STRING SLASH NUMBER duration duration
		{
			struct dhcp6_prefix pconf0, *pconf;		

			memset(&pconf0, 0, sizeof(pconf0));
			if (inet_pton(AF_INET6, $1, &pconf0.addr) != 1) {
				yywarn("invalid IPv6 address: %s", $1);
				free($1);
				return (-1);
			}
			free($1);
			/* validate other parameters later */
			pconf0.plen = $3;
			if ($4 < 0)
				pconf0.pltime = DHCP6_DURATITION_INFINITE;
			else
				pconf0.pltime = (u_int32_t)$4;
			if ($5 < 0)
				pconf0.vltime = DHCP6_DURATITION_INFINITE;
			else
				pconf0.vltime = (u_int32_t)$5;

			if ((pconf = malloc(sizeof(*pconf))) == NULL) {
				yywarn("can't allocate memory");
				return (-1);
			}
			*pconf = pconf0;

			$$ = pconf;
		}
	

duration:
		INFINITY
		{
			$$ = -1;
		}
	|	NUMBER
		{
			$$ = $1;
		}
	;

iaconf_list:
		{ $$ = NULL; }
	|	iaconf_list iaconf
		{
			struct cf_list *head;

			if ((head = $1) == NULL) {
				$2->next = NULL;
				$2->tail = $2;
				head = $2;
			} else {
				head->tail->next = $2;
				head->tail = $2;
			}

			$$ = head;
		}
	;

iaconf:
		prefix_interface { $$ = $1; }
	|	PREFIX prefixparam EOS
		{
			struct cf_list *l;

			MAKE_CFLIST(l, IACONF_PREFIX, $2, NULL);

			$$ = l;
		}
	;

prefix_interface:
	PREFIX_INTERFACE IFNAME BCL ifparams ECL EOS
	{
		struct cf_list *ifl;

		MAKE_CFLIST(ifl, IACONF_PIF, $2, $4);
		$$ = ifl;
	}
	;

ifparams:
		{ $$ = NULL; }
	|	ifparams ifparam
		{
			struct cf_list *head;

			if ((head = $1) == NULL) {
				$2->next = NULL;
				$2->tail = $2;
				head = $2;
			} else {
				head->tail->next = $2;
				head->tail = $2;
			}

			$$ = head;
		}
	;

ifparam:
		SLA_ID NUMBER EOS
		{
			struct cf_list *l;

			MAKE_CFLIST(l, IFPARAM_SLA_ID, NULL, NULL);
			l->num = $2;
			$$ = l;
		}
	|	SLA_LEN NUMBER EOS
		{
			struct cf_list *l;

			MAKE_CFLIST(l, IFPARAM_SLA_LEN, NULL, NULL);
			l->num = $2;
			$$ = l;
		}
	;

%%
/* supplement routines for configuration */
static int
add_namelist(new, headp)
	struct cf_namelist *new, **headp;
{
	struct cf_namelist *n;
	
	/* check for duplicated configuration */
	for (n = *headp; n; n = n->next) {
		if (strcmp(n->name, new->name) == 0) {
			yywarn("duplicated name: %s (ignored)",
			       new->name);
			cleanup_namelist(new);
			return (0);
		}
	}

	new->next = *headp;
	*headp = new;

	return (0);
}

/* free temporary resources */
static void
cleanup()
{
	cleanup_namelist(iflist_head);
	cleanup_namelist(hostlist_head);
	cleanup_namelist(iapdlist_head);

	cleanup_cflist(cf_dns_list);
}

static void
cleanup_namelist(head)
	struct cf_namelist *head;
{
	struct cf_namelist *ifp, *ifp_next;

	for (ifp = head; ifp; ifp = ifp_next) {
		ifp_next = ifp->next;
		cleanup_cflist(ifp->params);
		free(ifp->name);
		free(ifp);
	}
}

static void
cleanup_cflist(p)
	struct cf_list *p;
{
	struct cf_list *n;

	if (p == NULL)
		return;

	n = p->next;
	if (p->ptr)
		free(p->ptr);
	if (p->list)
		cleanup_cflist(p->list);
	free(p);

	cleanup_cflist(n);
}

#define config_fail() \
	do { cleanup(); configure_cleanup(); return (-1); } while(0)

int
cf_post_config()
{
	if (configure_ia(iapdlist_head, IATYPE_PD))
		config_fail();

	if (configure_interface(iflist_head))
		config_fail();

	if (configure_host(hostlist_head))
		config_fail();

	if (configure_global_option())
		config_fail();

	configure_commit();
	cleanup();
	return (0);
}
#undef config_fail

void
cf_init()
{
	iflist_head = NULL;
}
