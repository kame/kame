/*	$KAME: cfparse.y,v 1.6 2002/05/01 15:03:59 jinmei Exp $	*/

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

#include "config.h"

extern int lineno;
extern int cfdebug;

#define MAKE_CFLIST(l, t) do { \
	(l) = (struct cf_list *)malloc(sizeof(*(l))); \
	if ((l) == NULL) { \
		yywarn("can't allocate memory"); \
		return(-1); \
	} \
	memset((l), 0, sizeof(*(l))); \
	l->type = (t); \
	} while (0)

static struct cf_iflist *iflist_head, *piflist_head; 

extern int yylex __P((void));
static void cleanup __P((void));
static void cleanup_interface __P((struct cf_iflist *));
static void cleanup_cflist __P((struct cf_list *));
%}

%token INTERFACE IFNAME
%token PREFIX_INTERFACE SLA_ID
%token SEND
%token ALLOW
%token RAPID_COMMIT
%token INFO_ONLY
%token NUMBER SLASH EOS BCL ECL STRING

%union {
	int num;
	char* str;
	struct cf_list *list;
}

%type <str> IFNAME
%type <num> NUMBER
%type <list> declaration declarations dhcpoption ifparam ifparams

%%
statements:
		/* empty */
	|	statements statement
	;

statement:
		interface_statement
	|	prefix_interface_statement
	;

interface_statement:
	INTERFACE IFNAME BCL declarations ECL 
	{
		struct cf_iflist *ifl;

		if ((ifl = (struct cf_iflist *)malloc(sizeof(*ifl))) == NULL) {
			yywarn("memory allocation failed");
			return(-1);
		}
		memset(ifl, 0, sizeof(*ifl));
		ifl->ifname = $2;
		ifl->params = $4;
		if (add_interface(ifl, &iflist_head))
			return(-1);
	}
	;

prefix_interface_statement:
	PREFIX_INTERFACE IFNAME BCL ifparams ECL
	{
		struct cf_iflist *ifl;

		if ((ifl = (struct cf_iflist *)malloc(sizeof(*ifl))) == NULL) {
			yywarn("memory allocation failed");
			return(-1);
		}
		memset(ifl, 0, sizeof(*ifl));
		ifl->ifname = $2;
		ifl->params = $4;
		if (add_interface(ifl, &piflist_head))
			return(-1);
	}
	;

declarations:
		{ $$ = NULL; }
	|	declarations declaration
		{
			$2->next = $1; /* XXX reverse order */
			$$ = $2;
		}
	;
	
declaration:
		SEND dhcpoption EOS
		{
			struct cf_list *l;

			MAKE_CFLIST(l, DECL_SEND);
			l->list = $2;
			$$ = l;
		}
	|	INFO_ONLY EOS
		{
			struct cf_list *l;

			MAKE_CFLIST(l, DECL_INFO_ONLY);
			/* no value */
			$$ = l;
		}
	|	ALLOW dhcpoption EOS
		{
			struct cf_list *l;

			MAKE_CFLIST(l, DECL_ALLOW);
			l->list = $2;
			$$ = l;
		}
	;

dhcpoption:
	RAPID_COMMIT
	{
		struct cf_list *l;

		MAKE_CFLIST(l, DHCPOPT_RAPID_COMMIT);
		/* no value */
		$$ = l;
	}
	;

ifparams:
		{ $$ = NULL; }
	|	ifparams ifparam
		{
			$2->next = $1; /* XXX reverse order */
			$$ = $2;
		}
	;

ifparam:
	SLA_ID NUMBER EOS
	{
		struct cf_list *l;

		MAKE_CFLIST(l, IFPARAM_SLA_ID);
		l->num = $2;
		$$ = l;
	}
	;

%%
/* supplement routines for configuration */
static int
add_interface(new, headp)
	struct cf_iflist *new, **headp;
{
	struct cf_iflist *ifp;

	/* check for duplicated configuration */
	for (ifp = *headp; ifp; ifp = ifp->next) {
		if (strcmp(ifp->ifname, new->ifname) == 0) {
			yywarn("duplicated interface: %s (ignored)",
			       new->ifname);
			cleanup_interface(new);
			return(0);
		}
	}

	new->next = *headp;
	*headp = new;

	return(0);
}

/* free temporary resources */
static void
cleanup()
{
	cleanup_interface(iflist_head);
	cleanup_interface(piflist_head);
}

static void
cleanup_interface(head)
	struct cf_iflist *head;
{
	struct cf_iflist *ifp, *ifp_next;

	for (ifp = head; ifp; ifp = ifp_next) {
		ifp_next = ifp->next;
		cleanup_cflist(ifp->params);
		free(ifp->ifname);
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
	do { cleanup(); configure_cleanup(); return(-1); } while(0)

int
cf_post_config()
{
	if (configure_interface(iflist_head))
		config_fail();

	if (configure_prefix_interface(piflist_head))
		config_fail();

	configure_commit();
	cleanup();
	return(0);
}
#undef config_fail

void
cf_init()
{
	iflist_head = NULL;
}
