/*	$KAME: cfparse.y,v 1.9 2005/10/11 10:04:46 keiichi Exp $	*/

%{
/*
 * Copyright (C) 2005 WIDE Project.
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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"

extern FILE *yyin;

int yylex(void);
int yyparse(void);

static int config_mode;
static struct config_entry **config_result;

static struct config_entry *alloc_cfe(int);
static void free_cfe_list(struct config_entry *);
static void free_cfe(struct config_entry *);

%}

%token BCL ECL EOS SLASH
%token INTEGER
%token ADDRSTRING
%token DEBUG
%token NAMELOOKUP
%token COMMANDPORT
%token INTERFACE IFNAME
%token HOMEREGISTRATIONLIFETIME
%token PREFERENCE
%token KEYMANAGEMENT
%token PREFIXTABLE EXPLICIT IMPLICIT
%token STATICTUNNEL
%token IPV4MNPSUPPORT
%token IPV4DUMMYTUNNEL

%union {
	int number;
	char* string;
	struct config_entry *cfe;
}

%type <string> ADDRSTRING
%type <string> IFNAME
%type <string> registration_mode EXPLICIT IMPLICIT
%type <number> INTEGER
%type <cfe> statements statement
%type <cfe> debug_statement namelookup_statement
%type <cfe> commandport_statement
%type <cfe> homeregistrationlifetime_statement
%type <cfe> interface_statement
%type <cfe> preference_statement
%type <cfe> keymanagement_statement
%type <cfe> ipv4mnpsupport_statement
%type <cfe> prefixtable_config
%type <cfe> prefixtable_statements prefixtable_statement
%type <cfe> statictunnel_config
%type <cfe> statictunnel_statements statictunnel_statement
%type <cfe> ipv4dummytunnel_config
%type <cfe> ipv4dummytunnel_statements ipv4dummytunnel_statement

%%

config:
		statements
		{
			*config_result = $1;
		}
	;

statements:
		{ $$ = NULL; }
	|	statements statement
		{
			struct config_entry *cfe_head;

			cfe_head = $1;
			if (cfe_head == NULL) {
				$2->cfe_next = NULL;
				$2->cfe_tail = $2;
				cfe_head = $2;
			} else {
				cfe_head->cfe_tail->cfe_next = $2;
				cfe_head->cfe_tail = $2->cfe_tail;
			}

			$$ = cfe_head;
		}
	;

statement:
		debug_statement
	|	namelookup_statement
	|	commandport_statement
	|	interface_statement
	|	homeregistrationlifetime_statement
	|	preference_statement
	|	keymanagement_statement
	|	prefixtable_config
	|	statictunnel_config
	|	ipv4mnpsupport_statement
	|	ipv4dummytunnel_config
	;

debug_statement:
		DEBUG INTEGER EOS
		{
			struct config_entry *cfe;

			cfe = alloc_cfe(CFT_DEBUG);
			if (cfe == NULL)
				return (-1);
			cfe->cfe_number = $2;

			$$ = cfe;
		}
	;

namelookup_statement:
		NAMELOOKUP INTEGER EOS
		{
			struct config_entry *cfe;

			cfe = alloc_cfe(CFT_NAMELOOKUP);
			if (cfe == NULL)
				return (-1);
			cfe->cfe_number = $2;

			$$ = cfe;
		}
	;

commandport_statement:
		COMMANDPORT INTEGER EOS
		{
			struct config_entry *cfe;

			cfe = alloc_cfe(CFT_COMMANDPORT);
			if (cfe == NULL)
				return (-1);
			cfe->cfe_number = $2;

			$$ = cfe;
		}
	;

interface_statement:
		INTERFACE IFNAME BCL statements ECL EOS
		{
			struct config_entry *cfe;

			cfe = alloc_cfe(CFT_INTERFACE);
			if (cfe == NULL)
				return (-1);
			cfe->cfe_ptr = $2;
			cfe->cfe_list = $4;

			$$ = cfe;
		}
	;

homeregistrationlifetime_statement:
		HOMEREGISTRATIONLIFETIME INTEGER EOS
		{
			struct config_entry *cfe;

			cfe = alloc_cfe(CFT_HOMEREGISTRATIONLIFETIME);
			if (cfe == NULL)
				return (-1);
			cfe->cfe_number = $2;

			$$ = cfe;
		}
	;

preference_statement:
		PREFERENCE INTEGER EOS
		{
			struct config_entry *cfe;

			cfe = alloc_cfe(CFT_PREFERENCE);
			if (cfe == NULL)
				return (-1);
			cfe->cfe_number = $2;

			$$ = cfe;
		}
	;

keymanagement_statement:
		KEYMANAGEMENT INTEGER EOS
		{
			struct config_entry *cfe;

			cfe = alloc_cfe(CFT_KEYMANAGEMENT);
			if (cfe == NULL)
				return (-1);
			cfe->cfe_number = (($2 == 0) ? 0 : 1);

			$$ = cfe;
		}
	;

ipv4mnpsupport_statement:
		IPV4MNPSUPPORT INTEGER EOS
		{
			struct config_entry *cfe;

			cfe = alloc_cfe(CFT_IPV4MNPSUPPORT);
			if (cfe == NULL)
				return (-1);
			cfe->cfe_number = (($2 == 0) ? 0 : 1);

			$$ = cfe;
		}
	;

prefixtable_config:
		PREFIXTABLE BCL prefixtable_statements ECL EOS
		{
			struct config_entry *cfe;

			if (config_mode == CFM_CND ||
			    config_mode == CFM_MND) {
				printf("not supported\n");
				return (-1);
			}

			cfe = alloc_cfe(CFT_PREFIXTABLELIST);
			if (cfe == NULL) {
				free_cfe_list($3);
				return (-1);
			}
			cfe->cfe_list = $3;

			$$ = cfe;
		}
	;

prefixtable_statements:
		{ $$ = NULL; }
	|	prefixtable_statements prefixtable_statement
		{
			struct config_entry *cfe_head;

			cfe_head = $1;
			if (cfe_head == NULL) {
				$2->cfe_next = NULL;
				$2->cfe_tail = $2;
				cfe_head = $2;
			} else {
				cfe_head->cfe_tail->cfe_next = $2;
				cfe_head->cfe_tail = $2->cfe_tail;
			}

			$$ = cfe_head;
		}
	;

prefixtable_statement:
		ADDRSTRING ADDRSTRING SLASH INTEGER registration_mode INTEGER EOS
		{
			struct config_entry *cfe;
			struct config_prefixtable *cfpt;
			struct addrinfo hints, *res0;

			cfpt = (struct config_prefixtable *)
				malloc(sizeof(struct config_prefixtable));
			if (cfpt == NULL)
				return (-1);

			if (inet_pton(AF_INET6, $1,
			    &cfpt->cfpt_homeaddress) <= 0) {
				free(cfpt);
				return(-1);
			}

			memset(&hints, 0, sizeof(struct addrinfo));
			hints.ai_family = PF_UNSPEC;
			hints.ai_flags = AI_NUMERICHOST;
			if (getaddrinfo($2, NULL, &hints, &res0)) {
				printf("invalid prefix %s\n", $1);
				free(cfpt);
				return (-1);
			}
			memcpy(&cfpt->cfpt_ss_prefix, res0->ai_addr,
			    res0->ai_addrlen);
			freeaddrinfo(res0);
			cfpt->cfpt_prefixlen = $4;
			if (strcmp($5, "explicit") == 0)
				cfpt->cfpt_mode = CFPT_EXPLICIT;
			else
				cfpt->cfpt_mode = CFPT_IMPLICIT;
			cfpt->cfpt_binding_id = $6;

			cfe = alloc_cfe(CFT_PREFIXTABLE);
			if (cfe == NULL) {
				free(cfpt);
				return (-1);
			}				
			cfe->cfe_ptr = cfpt;

			$$ = cfe;
		}
	|	ADDRSTRING ADDRSTRING SLASH INTEGER registration_mode EOS
		{
			struct config_entry *cfe;
			struct config_prefixtable *cfpt;
			struct addrinfo hints, *res0;

			cfpt = (struct config_prefixtable *)
				malloc(sizeof(struct config_prefixtable));
			if (cfpt == NULL)
				return (-1);

			if (inet_pton(AF_INET6, $1,
			    &cfpt->cfpt_homeaddress) <= 0) {
				free(cfpt);
				return(-1);
			}

			memset(&hints, 0, sizeof(struct addrinfo));
			hints.ai_family = PF_UNSPEC;
			hints.ai_flags = AI_NUMERICHOST;
			if (getaddrinfo($2, NULL, &hints, &res0)) {
				printf("invalid prefix %s\n", $1);
				free(cfpt);
				return (-1);
			}
			memcpy(&cfpt->cfpt_ss_prefix, res0->ai_addr,
			    res0->ai_addrlen);
			freeaddrinfo(res0);
			cfpt->cfpt_prefixlen = $4;
			if (strcmp($5, "explicit") == 0)
				cfpt->cfpt_mode = CFPT_EXPLICIT;
			else
				cfpt->cfpt_mode = CFPT_IMPLICIT;
			cfpt->cfpt_binding_id = 0;

			cfe = alloc_cfe(CFT_PREFIXTABLE);
			if (cfe == NULL) {
				free(cfpt);
				return (-1);
			}				
			cfe->cfe_ptr = cfpt;

			$$ = cfe;
		}
	;

registration_mode:
		EXPLICIT
	|	IMPLICIT
	;

statictunnel_config:
		STATICTUNNEL BCL statictunnel_statements ECL EOS
		{
			struct config_entry *cfe;

			if (config_mode == CFM_CND ||
			    config_mode == CFM_MND) {
				printf("not supported\n");
				return (-1);
			}

			cfe = alloc_cfe(CFT_STATICTUNNELLIST);
			if (cfe == NULL) {
				free_cfe_list($3);
				return (-1);
			}
			cfe->cfe_list = $3;

			$$ = cfe;
		}
	;

statictunnel_statements:
		{ $$ = NULL; }
	|	statictunnel_statements statictunnel_statement
		{
			struct config_entry *cfe_head;

			cfe_head = $1;
			if (cfe_head == NULL) {
				$2->cfe_next = NULL;
				$2->cfe_tail = $2;
				cfe_head = $2;
			} else {
				cfe_head->cfe_tail->cfe_next = $2;
				cfe_head->cfe_tail = $2->cfe_tail;
			}

			$$ = cfe_head;
		}
	;

statictunnel_statement:
		IFNAME ADDRSTRING INTEGER EOS
		{
			struct config_entry *cfe;
			struct config_static_tunnel *cfst;

			cfst = (struct config_static_tunnel *)
				malloc(sizeof(struct config_static_tunnel));
			if (cfst == NULL)
				return (-1);

			cfst->cfst_ifname = $1;
			if (inet_pton(AF_INET6, $2,
				&cfst->cfst_homeaddress) <= 0) {
				free(cfst);
				return (-1);
			}
			cfst->cfst_binding_id = $3;

			cfe = alloc_cfe(CFT_STATICTUNNEL);
			if (cfe == NULL) {
				free(cfst);
				return (-1);
			}				
			cfe->cfe_ptr = cfst;

			$$ = cfe;
		}
	|	IFNAME ADDRSTRING EOS
		{
			struct config_entry *cfe;
			struct config_static_tunnel *cfst;

			cfst = (struct config_static_tunnel *)
				malloc(sizeof(struct config_static_tunnel));
			if (cfst == NULL)
				return (-1);

			cfst->cfst_ifname = $1;
			if (inet_pton(AF_INET6, $2,
				&cfst->cfst_homeaddress) <= 0) {
				free(cfst);
				return (-1);
			}
			cfst->cfst_binding_id = 0;

			cfe = alloc_cfe(CFT_STATICTUNNEL);
			if (cfe == NULL) {
				free(cfst);
				return (-1);
			}				
			cfe->cfe_ptr = cfst;

			$$ = cfe;
		}
	;

ipv4dummytunnel_config:
		IPV4DUMMYTUNNEL BCL ipv4dummytunnel_statements ECL EOS
		{
			struct config_entry *cfe;

			if (config_mode == CFM_CND ||
			    config_mode == CFM_MND) {
				printf("not supported\n");
				return (-1);
			}

			cfe = alloc_cfe(CFT_IPV4DUMMYTUNNELLIST);
			if (cfe == NULL) {
				free_cfe_list($3);
				return (-1);
			}
			cfe->cfe_list = $3;

			$$ = cfe;
		}
	;

ipv4dummytunnel_statements:
		{ $$ = NULL; }
	|	ipv4dummytunnel_statements ipv4dummytunnel_statement
		{
			struct config_entry *cfe_head;

			cfe_head = $1;
			if (cfe_head == NULL) {
				$2->cfe_next = NULL;
				$2->cfe_tail = $2;
				cfe_head = $2;
			} else {
				cfe_head->cfe_tail->cfe_next = $2;
				cfe_head->cfe_tail = $2->cfe_tail;
			}

			$$ = cfe_head;
		}
	;

ipv4dummytunnel_statement:
		IFNAME ADDRSTRING ADDRSTRING EOS
		{
			struct config_entry *cfe;
			struct config_ipv4_dummy_tunnel *cfdt;

			cfdt = (struct config_ipv4_dummy_tunnel *)
			    malloc(sizeof(struct config_ipv4_dummy_tunnel));
			if (cfdt == NULL)
				return (-1);

			cfdt->cfdt_ifname = $1;
			if (inet_pton(AF_INET, $2,
				&cfdt->cfdt_mr_address) <= 0) {
				free(cfdt);
				return (-1);
			}
			if (inet_pton(AF_INET, $3,
				&cfdt->cfdt_ha_address) <= 0) {
				free(cfdt);
				return (-1);
			}

			cfe = alloc_cfe(CFT_IPV4DUMMYTUNNEL);
			if (cfe == NULL) {
				free(cfdt);
				return (-1);
			}				
			cfe->cfe_ptr = cfdt;

			$$ = cfe;
		}
	;

%%

int
parse(mode, filename, result)
	int mode;
	const char *filename;
	struct config_entry **result;
{
	config_mode = mode;
	config_result = result;

	yyin = fopen(filename, "r");
	if (yyin == NULL)
		return (-1);

	while (!feof(yyin)) {
		if (yyparse()) {
			fclose(yyin);
			return (-1);
		}
	}
	fclose(yyin);

	return (0);
}

void
yyerror(s)
	char *s;
{
	fprintf(stderr, "%s\n", s);
}

int
yywrap()
{
	return (1);
}

static struct config_entry *
alloc_cfe(type)
	int type;
{
	struct config_entry *cfe;

	cfe = (struct config_entry *)malloc(sizeof(struct config_entry));
	if (cfe == NULL)
		return (NULL);
	memset(cfe, 0, sizeof(struct config_entry));

	cfe->cfe_type = type;
	cfe->cfe_tail = cfe;

	return (cfe);
}

static void
free_cfe(cfe)
	struct config_entry *cfe;
{
	if (cfe->cfe_ptr)
		free(cfe->cfe_ptr);
	if (cfe->cfe_list)
		free_cfe_list(cfe->cfe_list);
	free(cfe);
}

static void
free_cfe_list(cfe_list)
	struct config_entry *cfe_list;
{
	struct config_entry *next;

	while (cfe_list) {
		next = cfe_list->cfe_next;
		free_cfe(cfe_list);
		cfe_list = next;
	}
}
