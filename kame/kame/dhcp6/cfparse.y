/*	$KAME: cfparse.y,v 1.2 2002/05/01 10:30:34 jinmei Exp $	*/

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

#define cprint if (cfdebug) printf

extern int lineno;
extern int cfdebug;

static struct cf_iflist *iflist_head; 

extern int yylex __P((void));
static void cleanup __P((void));
static void cleanup_interface __P((void));
static void cleanup_ifconf __P((struct cf_ifconf *));
static void cleanup_declaration __P((struct cf_declaration *));
static void cleanup_dhcpoption __P((struct cf_dhcpoption *));
%}

%token INTERFACE IFNAME
%token SEND
%token RAPID_COMMIT
%token INFO_ONLY
%token NUMBER SLASH EOS BCL ECL STRING

%union {
	unsigned long num;
	char* str;
	struct cf_declaration *decl;
	struct cf_dhcpoption *dhcpopt;
}

%type <str> IFNAME
%type <decl> declaration declarations
%type <dhcpopt> dhcpoption

%%
statements:
		/* empty */
	|	statements statement
	;

statement:
	interface_statement
	;

interface_statement:
	INTERFACE IFNAME BCL declarations ECL 
	{
		struct cf_ifconf *ifc;

		if ((ifc = (struct cf_ifconf *)malloc(sizeof(*ifc))) == NULL) {
			yywarn("memory allocation failed");
			return(-1);
		}
		memset(ifc, 0, sizeof(*ifc));
		ifc->ifname = $2;
		ifc->decl = $4;
		ifc->line = lineno;
		if (add_interface(ifc))
			return(-1);
	}
	;

declarations:
		{ $$ = NULL; }
	|	declarations declaration
		{
			struct cf_declaration *d, *dp, *dhead;

			$2->decl_next = $1; /* XXX reverse order */
			$$ = $2;
		}
	;
	
declaration:
		SEND dhcpoption EOS
		{
			struct cf_declaration *d;

			d = (struct cf_declaration *)malloc(sizeof(*d));
			if (d == NULL) {
				yywarn("can't allocate memory");
				return(-1);
			}
			memset(d, 0, sizeof(*d));
			d->decl_type = DECL_SEND;
			d->decl_val = $2;
			$$ = d;
		}
	|	INFO_ONLY EOS
		{
			struct cf_declaration *d;

			d = (struct cf_declaration *)malloc(sizeof(*d));
			if (d == NULL) {
				yywarn("can't allocate memory");
				return(-1);
			}
			memset(d, 0, sizeof(*d));
			d->decl_type = DECL_INFO_ONLY;
			$$ = d;
		}
	|	ALLOW dhcpoption EOS
		{
			struct cf_declaration *d;

			d = (struct cf_declaration *)malloc(sizeof(*d));
			if (d == NULL) {
				yywarn("can't allocate memory");
				return(-1);
			}
			memset(d, 0, sizeof(*d));
			d->decl_type = DECL_ALLOW;
			d->decl_val = $2;
			$$ = d;
		}
	;

dhcpoption:
	RAPID_COMMIT
	{
		struct cf_dhcpoption *opt;
		
		if ((opt = (struct cf_dhcpoption *)malloc(sizeof(*opt)))
		    == NULL) {
			yywarn("can't allocate memory");
			return(-1);
		}
		memset(opt, 0, sizeof(*opt));
		opt->dhcpopt_type = DHCPOPT_RAPID_COMMIT;
		$$ = opt;
	}
	;

%%
/* supplement routines for configuration */
static int
add_interface(conf)
	struct cf_ifconf *conf;
{
	struct cf_iflist *ifp;

	/* check for duplicated configuration */
	for (ifp = iflist_head; ifp; ifp = ifp->if_next) {
		if (strcmp(ifp->if_conf->ifname, conf->ifname) == 0) {
			yywarn("duplicated interface: %s", conf->ifname);
			cleanup_ifconf(conf);
			return(0);
		}
	}

	if ((ifp = malloc(sizeof(*ifp))) == NULL) {
		yywarn("memory allocation failed");
		return(-1);
	}
	memset(ifp, 0, sizeof(*ifp));
	ifp->if_next = iflist_head;
	iflist_head = ifp;
	ifp->if_conf = conf;

	cprint("add interface %s at %d\n", conf->ifname, lineno);

	return(0);
}

/* free temporary resources */
static void
cleanup()
{
	cleanup_interface();
}

static void
cleanup_interface()
{
	struct cf_iflist *ifp, *ifp_next;

	for (ifp = iflist_head; ifp; ifp = ifp_next) {
		ifp_next = ifp->if_next;
		cleanup_ifconf(ifp->if_conf);
		free(ifp);
	}
}

static void
cleanup_ifconf(conf)
	struct cf_ifconf *conf;
{
	if (conf->decl)
		cleanup_declaration(conf->decl);
	free(conf->ifname);
}

static void
cleanup_declaration(decl)
	struct cf_declaration *decl;
{
	struct cf_declaration *next;

	if (decl == NULL)
		return;
	next = decl->decl_next;

	switch(decl->decl_type) {
	case DECL_SEND:
		cleanup_dhcpoption(decl->decl_val);
		break;
	case DECL_INFO_ONLY:	/* no value */
		break;
	default:
		yyerror("cleanup_declaration: unexpected declaration");
	}
	free(decl);

	cleanup_declaration(next);	
}

static void
cleanup_dhcpoption(opt)
	struct cf_dhcpoption *opt;
{
	struct cf_dhcpoption *next;

	if (opt == NULL)
		return;
	next = opt->dhcpopt_next;

	if (opt->dhcpopt_val)
		free(opt->dhcpopt_val);
	free(opt);

	cleanup_dhcpoption(next);
}

#define config_fail() \
	do { cleanup(); configure_cleanup(); return(-1); } while(0)

int
cf_post_config()
{
	if (configure_interface(iflist_head))
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
