%{
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"

extern FILE *yyin;

int config_mode;
struct config_entry *config_result;

int yylex(void);
int yyparse(void);

int parse(int, FILE *);

static struct config_entry *alloc_cfe(int);
static void free_cfe_list(struct config_entry *);
static void free_cfe(struct config_entry *);

%}

%token BCL ECL EOS SLASH
%token INTEGER
%token ADDRSTRING
%token DEBUG
%token NAMELOOKUP
%token INTERFACE IFNAME MIPIFNAME
%token HOMEREGISTRATIONLIFETIME
%token PREFERENCE
%token PREFIXTABLE EXPLICIT IMPLICIT

%union {
	int number;
	char* string;
	struct config_entry *cfe;
}

%type <string> ADDRSTRING
%type <string> MIPIFNAME IFNAME
%type <string> registration_mode EXPLICIT IMPLICIT
%type <number> INTEGER
%type <cfe> statements statement
%type <cfe> debug_statement namelookup_statement
%type <cfe> homeregistrationlifetime_statement
%type <cfe> mipinterface_statement interface_statement
%type <cfe> preference_statement
%type <cfe> prefixtable_config
%type <cfe> prefixtable_statements prefixtable_statement

%%

config:
		statements
		{
			config_result = $1;
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
	|	mipinterface_statement
	|	interface_statement
	|	homeregistrationlifetime_statement
	|	preference_statement
	|	prefixtable_config
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

interface_statement:
		INTERFACE IFNAME EOS
		{
			struct config_entry *cfe;

			cfe = alloc_cfe(CFT_INTERFACE);
			if (cfe == NULL)
				return (-1);
			cfe->cfe_ptr = $2;

			$$ = cfe;
		}
	;

mipinterface_statement:
		INTERFACE MIPIFNAME EOS
		{
			struct config_entry *cfe;

			cfe = alloc_cfe(CFT_MOBILEINTERFACE);
			if (cfe == NULL)
				return (-1);
			cfe->cfe_ptr = $2;

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

preference_statement
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

			cfpt = (struct config_prefixtable *)
				malloc(sizeof(struct config_prefixtable));
			if (cfpt == NULL)
				return (-1);

			if (inet_pton(AF_INET6, $1,
				&cfpt->cfpt_homeaddress) <= 0) {
				free(cfpt);
				return (-1);
			}
			if (inet_pton(AF_INET6, $2,
				&cfpt->cfpt_prefix) <= 0) {
				free(cfpt);
				return (-1);
			}
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

			cfpt = (struct config_prefixtable *)
				malloc(sizeof(struct config_prefixtable));
			if (cfpt == NULL)
				return (-1);

			if (inet_pton(AF_INET6, $1,
				&cfpt->cfpt_homeaddress) <= 0) {
				free(cfpt);
				return (-1);
			}
			if (inet_pton(AF_INET6, $2,
				&cfpt->cfpt_prefix) <= 0) {
				free(cfpt);
				return (-1);
			}
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

%%

int
parse(mode, in)
	int mode;
	FILE *in;
{
	config_mode = mode;

	yyin = in;
	while (!feof(yyin)) {
		if (yyparse())
			return (-1);
	}
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
